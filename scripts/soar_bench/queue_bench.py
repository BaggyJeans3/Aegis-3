#!/usr/bin/env python3
"""
Aegis-3 SOAR 큐 처리량 / 정합 점검 도구
=========================================

Proxy·사이드카가 Redis(aegis:security-events)에 LPUSH 하는 것과 '같은 모양'의 합성 이벤트를
N건 넣고, Celery worker 가 전부 소비해 MongoDB 에 저장할 때까지 지켜보며 다음을 측정한다.

  [처리량]  적재 속도, 소비(drain) 속도 eps, 큐 최대 적체 길이
  [지연]    이벤트 timestamp → Mongo created_at 까지 end-to-end 지연 p50/p95/p99/max
  [정합]    유실(넣었는데 Mongo 에 없음) / 중복 저장 / 필수 필드 누락 / 점수-등급 불일치

사용 예 (EC2, 실제 Mongo):
  python3 scripts/soar_bench/queue_bench.py \
      --redis redis://localhost:6379/0 \
      --mongo "mongodb://aegis_user:<PW>@localhost:27017/aegis_logs?authSource=admin" \
      --collection traffic_logs --count 5000 --rate 500

  ※ docker-compose 는 mongodb 포트를 호스트에 노출하지 않는다. EC2 에서는 아래처럼 컨테이너 안에서 실행:
     sudo docker cp scripts/soar_bench/queue_bench.py aegis-soar-worker:/tmp/
     sudo docker exec -e MONGO_PASSWORD=... aegis-soar-worker python /tmp/queue_bench.py \
         --redis redis://redis:6379/0 --mongo-from-env --count 5000 --rate 500

안전장치:
  - 기본 이벤트 믹스는 LLM 을 부르지 않도록 설계했다 (detection-engine 점수 < 30).
      access_event(rate_only, IP 풀 분산) 80% + waf_blocked(엔진 점수 0, Mongo 에서만 CRITICAL 격상) 20%
    단, --mix 에 honeypot 을 넣으면 엔진 점수 40 → 시연 설정(AI_RULE_THRESHOLD=30)에서는 LLM 이 호출된다.
  - 모든 이벤트는 event_id 가 'bench-<run_id>-' 로 시작하고 IP 는 벤치마크 전용 대역 198.18.0.0/15 를 쓴다.
    --cleanup 으로 측정 후 해당 문서를 지운다.
"""

import argparse
import json
import os
import random
import statistics
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import quote_plus

try:
    import redis
except ImportError:  # pragma: no cover
    sys.exit("redis 패키지가 필요합니다: pip install redis")

QUEUE = "aegis:security-events"
CELERY_BROKER_QUEUE = "celery"

REQUIRED_ANALYSIS_KEYS = ("risk_score", "level", "alert", "rule_hits", "reasons", "action_on_match")


# ---------------------------------------------------------------------------
# 합성 이벤트 (proxy/app.js buildAnalyzerEvent, nginx/sidecar.js maybePushBlockedEvent 와 동일 필드)
# ---------------------------------------------------------------------------

def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _bench_ip(i):
    # 198.18.0.0/15 (RFC 2544 벤치마크 대역) 안에서 1024개 IP 로 분산 → 요청량 룰(R-RATE) 누적 방지
    n = i % 1024
    return f"198.18.{n // 256}.{n % 256}"


def make_event(kind, run_id, seq, tenant_id=None):
    event_id = f"bench-{run_id}-{seq:07d}"
    base = {
        "event_id": event_id,
        "trace_id": f"trace-{event_id}",
        "timestamp": _now_iso(),
        "tenant_id": tenant_id,
        "company_name": "Bench Corp" if tenant_id else None,
        "ip": _bench_ip(seq),
        "session_id": "unknown",
        "method": "GET",
        "host": "bench.aegis3.local",
        "query": "",
        "body": "",
        "route_id": None,
        "route_description": "queue_bench",
    }
    headers = {
        "user-agent": "aegis-queue-bench/1.0",
        "x-forwarded-for": f"{base['ip']}, 127.0.0.1",
        "cf-connecting-ip": None,
        "authorization": None,
        "content-type": None,
    }
    if kind == "access":
        base.update(event_type="access_event", analysis_profile="rate_only", path="/index.html",
                    headers=headers, status_code=0, action_on_match="proxy")
    elif kind == "waf":
        base.update(event_type="waf_blocked", analysis_profile="full", path="/",
                    query="id=1%27%20OR%20%271%27%3D%271", headers={}, status_code=403,
                    action_on_match="block", waf_rule_hits=["942100", "949110"])
    elif kind == "honeypot":
        base.update(event_type="honeypot_hit", analysis_profile="full", path="/.env",
                    headers=headers, status_code=200, action_on_match="honeypot")
    elif kind == "noroute":
        base.update(event_type="no_matching_route", analysis_profile="full", path=f"/bench-{seq}",
                    headers=headers, status_code=404, action_on_match="no_route")
    else:
        raise ValueError(kind)
    return base


def parse_mix(mix):
    """'access:80,waf:20' → [('access',0.8),('waf',0.2)]"""
    parts = []
    for token in mix.split(","):
        kind, weight = token.split(":")
        parts.append((kind.strip(), float(weight)))
    total = sum(w for _, w in parts)
    return [(k, w / total) for k, w in parts]


# ---------------------------------------------------------------------------
# 저장소(싱크) 어댑터 — 실제 Mongo 또는 로컬 하네스용 Redis 리스트
# ---------------------------------------------------------------------------

class MongoSink:
    def __init__(self, uri, db_name, collection):
        from pymongo import MongoClient
        self.client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        self.coll = self.client[db_name][collection]

    def fetch(self, prefix):
        cursor = self.coll.find(
            {"event_id": {"$regex": f"^{prefix}"}},
            {"event_id": 1, "raw_event.timestamp": 1, "created_at": 1, "security_analysis": 1},
        )
        return list(cursor)

    def count(self, prefix):
        # 중복 저장이 있어도 '고유 event_id' 기준으로 완료를 판정한다
        return len(self.coll.distinct("event_id", {"event_id": {"$regex": f"^{prefix}"}}))

    def cleanup(self, prefix):
        return self.coll.delete_many({"event_id": {"$regex": f"^{prefix}"}}).deleted_count


class RedisListSink:
    """scripts/soar_bench/local/bench_worker.py 가 Mongo 대신 문서를 쌓는 Redis 리스트."""

    def __init__(self, url, key="bench:mongo_docs"):
        self.r = redis.from_url(url, decode_responses=True)
        self.key = key

    def _all(self):
        return [json.loads(x) for x in self.r.lrange(self.key, 0, -1)]

    def fetch(self, prefix):
        return [d for d in self._all() if str(d.get("event_id", "")).startswith(prefix)]

    def count(self, prefix):
        return len({d.get("event_id") for d in self.fetch(prefix)})

    def cleanup(self, prefix):
        n = self.r.llen(self.key)
        self.r.delete(self.key)
        return n


def _mongo_uri_from_env():
    user = os.getenv("MONGO_USER", "aegis_user")
    pw = os.getenv("MONGO_PASSWORD")
    if not pw:
        sys.exit("--mongo-from-env 는 MONGO_PASSWORD 환경변수가 필요합니다")
    host = os.getenv("MONGO_HOST", "mongodb")
    port = os.getenv("MONGO_PORT", "27017")
    return f"mongodb://{quote_plus(user)}:{quote_plus(pw)}@{host}:{port}/aegis_logs?authSource=admin"


# ---------------------------------------------------------------------------
# 측정
# ---------------------------------------------------------------------------

def _parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def pct(values, p):
    if not values:
        return None
    values = sorted(values)
    k = max(0, min(len(values) - 1, int(round(p / 100 * (len(values) - 1)))))
    return values[k]


def level_for(score):
    if score <= 24:
        return "LOW"
    if score <= 49:
        return "SUSPICIOUS"
    if score <= 80:
        return "HIGH"
    return "CRITICAL"


def check_consistency(docs, expected_ids):
    seen = {}
    for d in docs:
        seen[d["event_id"]] = seen.get(d["event_id"], 0) + 1
    missing = sorted(set(expected_ids) - set(seen))
    duplicates = {k: v for k, v in seen.items() if v > 1}

    field_errors, level_mismatch = [], []
    for d in docs:
        sa = d.get("security_analysis") or {}
        lacking = [k for k in REQUIRED_ANALYSIS_KEYS if k not in sa]
        if lacking:
            field_errors.append((d["event_id"], lacking))
            continue
        score = sa.get("risk_score")
        if isinstance(score, (int, float)) and sa.get("level") != level_for(score):
            level_mismatch.append((d["event_id"], score, sa.get("level")))
    return missing, duplicates, field_errors, level_mismatch


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--redis", default=os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    ap.add_argument("--queue", default=QUEUE)
    ap.add_argument("--count", type=int, default=2000, help="적재할 이벤트 수")
    ap.add_argument("--rate", type=float, default=0, help="초당 적재 속도(0=최대 속도로 한 번에)")
    ap.add_argument("--mix", default="access:80,waf:20", help="이벤트 비율. access,waf,honeypot,noroute")
    ap.add_argument("--tenant-id", default=None)
    ap.add_argument("--timeout", type=float, default=300, help="drain 대기 최대 초")
    ap.add_argument("--mongo", default=None, help="MongoDB URI (실환경)")
    ap.add_argument("--mongo-from-env", action="store_true", help="MONGO_* 환경변수로 URI 조립(워커 컨테이너 안)")
    ap.add_argument("--db", default="aegis_logs")
    ap.add_argument("--collection", default=os.getenv("MONGO_COLLECTION_NAME", "traffic_logs"))
    ap.add_argument("--local-sink", default=None, help="로컬 하네스: 문서가 쌓이는 Redis URL (예: redis://localhost:6379/2)")
    ap.add_argument("--cleanup", action="store_true", help="측정 후 bench 문서 삭제")
    ap.add_argument("--json-out", default=None, help="결과를 JSON 파일로 저장")
    args = ap.parse_args()

    r = redis.from_url(args.redis, decode_responses=True)
    r.ping()

    if args.local_sink:
        sink = RedisListSink(args.local_sink)
    else:
        uri = _mongo_uri_from_env() if args.mongo_from_env else args.mongo
        if not uri:
            sys.exit("--mongo, --mongo-from-env, --local-sink 중 하나가 필요합니다")
        sink = MongoSink(uri, args.db, args.collection)

    run_id = uuid.uuid4().hex[:8]
    prefix = f"bench-{run_id}-"
    mix = parse_mix(args.mix)
    kinds = [k for k, _ in mix]
    weights = [w for _, w in mix]
    rng = random.Random(42)

    backlog_before = r.llen(args.queue)
    print(f"[bench] run_id={run_id} count={args.count} rate={args.rate or 'max'} mix={args.mix}")
    if backlog_before:
        print(f"[bench] ⚠ 시작 시점 큐에 이미 {backlog_before}건이 쌓여 있음 — 측정값에 영향")

    # ---------------- 적재 ----------------
    expected = []
    t0 = time.time()
    pipe = r.pipeline(transaction=False)
    for seq in range(args.count):
        ev = make_event(rng.choices(kinds, weights)[0], run_id, seq, args.tenant_id)
        expected.append(ev["event_id"])
        pipe.lpush(args.queue, json.dumps(ev))
        if args.rate > 0:
            pipe.execute()
            target = t0 + (seq + 1) / args.rate
            delay = target - time.time()
            if delay > 0:
                time.sleep(delay)
        elif len(pipe) >= 500:
            pipe.execute()
    pipe.execute()
    push_secs = time.time() - t0
    print(f"[bench] 적재 완료: {args.count}건 / {push_secs:.2f}s ({args.count / max(push_secs, 1e-9):.0f} eps)")

    # ---------------- 소비 관찰 ----------------
    max_queue, max_broker = 0, 0
    timeline = []
    stored = 0
    last_progress = time.time()
    while True:
        qlen = r.llen(args.queue)
        blen = r.llen(CELERY_BROKER_QUEUE)
        stored = sink.count(prefix)
        max_queue, max_broker = max(max_queue, qlen), max(max_broker, blen)
        elapsed = time.time() - t0
        timeline.append({"t": round(elapsed, 1), "queue": qlen, "broker": blen, "stored": stored})
        print(f"  t={elapsed:6.1f}s  aegis-queue={qlen:6d}  celery-broker={blen:6d}  stored={stored:6d}/{args.count}")
        if stored >= args.count:
            break
        if timeline[-1]["stored"] != (timeline[-2]["stored"] if len(timeline) > 1 else -1):
            last_progress = time.time()
        if time.time() - t0 > args.timeout:
            print("[bench] ⚠ timeout — 모두 저장되지 않음")
            break
        if time.time() - last_progress > 30 and qlen == 0 and blen == 0:
            print("[bench] ⚠ 30초간 진척 없음 + 큐 비어 있음 — 유실 가능성")
            break
        time.sleep(1)
    total_secs = time.time() - t0

    # ---------------- 분석 ----------------
    docs = sink.fetch(prefix)
    latencies = []
    for d in docs:
        start = _parse_ts((d.get("raw_event") or {}).get("timestamp"))
        end = _parse_ts(d.get("created_at"))
        if start and end:
            latencies.append((end - start).total_seconds() * 1000)

    missing, dups, field_errors, level_mismatch = check_consistency(docs, expected)
    drain_eps = len({d["event_id"] for d in docs}) / total_secs if total_secs else 0

    result = {
        "run_id": run_id,
        "count": args.count,
        "mix": args.mix,
        "push_seconds": round(push_secs, 2),
        "total_seconds": round(total_secs, 2),
        "drain_eps": round(drain_eps, 1),
        "max_queue_backlog": max_queue,
        "max_broker_backlog": max_broker,
        "latency_ms": {
            "p50": round(pct(latencies, 50), 1) if latencies else None,
            "p95": round(pct(latencies, 95), 1) if latencies else None,
            "p99": round(pct(latencies, 99), 1) if latencies else None,
            "max": round(max(latencies), 1) if latencies else None,
            "mean": round(statistics.mean(latencies), 1) if latencies else None,
        },
        "consistency": {
            "stored_unique": len({d["event_id"] for d in docs}),
            "missing": len(missing),
            "duplicates": len(dups),
            "field_errors": len(field_errors),
            "level_mismatch": len(level_mismatch),
            "missing_sample": missing[:5],
            "field_error_sample": field_errors[:3],
            "level_mismatch_sample": level_mismatch[:3],
        },
        "timeline": timeline,
    }

    c = result["consistency"]
    lat = result["latency_ms"]
    print("\n========================================")
    print(f" SOAR 큐 벤치 결과  run_id={run_id}")
    print("========================================")
    print(f" 이벤트        : {args.count}건  (mix {args.mix})")
    print(f" 전체 소요     : {total_secs:.1f}s   소비 처리량: {drain_eps:.1f} eps")
    print(f" 최대 적체     : aegis 큐 {max_queue}건 / celery 브로커 {max_broker}건")
    print(f" E2E 지연(ms)  : p50 {lat['p50']}  p95 {lat['p95']}  p99 {lat['p99']}  max {lat['max']}")
    print(f" 정합          : 저장 {c['stored_unique']}  유실 {c['missing']}  중복 {c['duplicates']}  "
          f"필드누락 {c['field_errors']}  점수-등급 불일치 {c['level_mismatch']}")
    if c["level_mismatch"]:
        print("   (점수-등급 불일치는 확정 악성 이벤트의 CRITICAL 격상이 아닌 경우에만 문제)")
    print("========================================")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"[bench] 결과 저장: {args.json_out}")

    if args.cleanup:
        print(f"[bench] 정리: {sink.cleanup(prefix)}건 삭제")

    ok = c["missing"] == 0 and c["duplicates"] == 0 and c["field_errors"] == 0
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
