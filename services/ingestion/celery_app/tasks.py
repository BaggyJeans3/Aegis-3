import os
import json
import time
import requests
from datetime import datetime
from urllib.parse import quote_plus, unquote, unquote_plus
from pymongo import MongoClient

from celery_app import celery_app, redis_client
from ai_engine import generate_waf_rule_with_feedback

import re
import hashlib


# ============================================================
# Worker 설정
# ============================================================

# Redis Queue 이름
# Proxy가 Redis에 LPUSH하는 키와 반드시 같아야 함
REDIS_QUEUE_NAME = os.getenv("REDIS_QUEUE_NAME", "aegis:security-events")

# Risk Score Engine 주소
# Docker 내부 통신에서는 localhost가 아니라 서비스명을 써야 함
# docker-compose에서 risk score 엔진 서비스명을 detection-engine으로 만들면 아래 기본값 그대로 사용
RISK_ANALYZER_URL = os.getenv(
    "RISK_ANALYZER_URL",
    "http://detection-engine:5000/analyze"
)

# MongoDB 저장 설정
MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://mongodb:27017/aegis_logs"
)

MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "aegis_logs")
MONGO_COLLECTION_NAME = os.getenv("MONGO_COLLECTION_NAME", "security_logs")

# AI 룰 생애주기 이벤트(생성·관찰 매칭·승격·보관·재무장) — 오탐율/탐지율 실험 로그
# worker 는 생성 이벤트를 직접 저장하고, sidecar 는 이 큐에 LPUSH → consume 태스크가 적재.
AI_RULE_EVENT_QUEUE = os.getenv("AI_RULE_EVENT_QUEUE", "aegis:ai-rule-events")
AI_RULE_EVENTS_COLLECTION = os.getenv("AI_RULE_EVENTS_COLLECTION", "ai_rule_events")

# AI 룰 생성 임계값 및 Nginx 사이드카(룰 주입) 엔드포인트
AI_RULE_THRESHOLD = int(os.getenv("AI_RULE_THRESHOLD", "80"))
NGINX_SIDECAR_URL = os.getenv(
    "NGINX_SIDECAR_URL",
    "http://nginx:4000/api/v1/rules/inject"
)

# analyzer(통합 대응 엔진) 보고 엔드포인트 — 고위험 시 CF 차단 + Slack + Email 트리거
ANALYZER_REPORT_URL = os.getenv(
    "ANALYZER_REPORT_URL",
    "http://analyzer:5000/api/v1/report"
)


# ============================================================
# [Aegis-3 SOAR] 작업 7 — 공격 클러스터링
# 비슷한 공격 패턴은 LLM 재호출 없이 캐시된 결과 재사용
# ============================================================

CLUSTER_TTL_SECONDS = int(os.getenv("CLUSTER_TTL_SECONDS", "300"))  # 5분
FP_THRESHOLD = int(os.getenv("FP_THRESHOLD", "3"))  # 오탐지 의심 임계값


def _sort_query_params(query: str) -> str:
    """
    쿼리 파라미터를 키 기준으로 정렬해 순서 무관 정규화한다.
    a=1&b=2 와 b=2&a=1 을 동일 키로 묶기 위함(의미 보존).
    """
    if not query:
        return ""
    parts = [p for p in query.split("&") if p]
    parts.sort()
    return "&".join(parts)


def normalize_attack_log(raw_event: dict) -> str:
    """
    공격 로그에서 IP·세션·타임스탬프 등 변동 요소를 제거하고
    공격 패턴의 본질만 남긴 정규화 문자열을 반환한다.

    '표현만 다른 동일 공격'을 같은 키로 모으기 위해 의미 보존 정규화를 수행한다
    (URL 디코딩 → 파라미터 키 정렬 → 토큰/숫자 치환). 단, 서로 다른 내용을 같게
    만드는 변형(키워드 토큰화 등)은 false-merge 위험이 있어 하지 않는다.
    """
    method = (raw_event.get("method") or "").upper()
    path = (raw_event.get("path") or "").lower()
    query = raw_event.get("query") or ""
    body = raw_event.get("body") or ""
    ua = (raw_event.get("headers", {}).get("user-agent") or "").lower()

    # 1. URL 디코딩 — %27 vs ' 처럼 인코딩만 다른 페이로드를 동일화.
    #    query 는 form 의미상 '+'→공백(unquote_plus), body(JSON 등)는 '+' 보존(unquote).
    try:
        query = unquote_plus(query)
    except Exception:
        pass
    try:
        body = unquote(body)
    except Exception:
        pass
    query = query.lower()
    body = body.lower()

    # 2. 쿼리 파라미터 키 정렬 (파라미터 순서만 다른 동일 공격 통일)
    query = _sort_query_params(query)

    text = f"{method} {path}?{query} body={body} ua={ua}"

    # 3. 토큰/UUID 먼저 치환 (숫자 치환보다 앞서야 hex 런이 깨지지 않음)
    text = re.sub(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "X",
        text,
    )  # UUID
    text = re.sub(r"[a-f0-9]{16,}", "X", text)  # 긴 hex(세션 토큰/해시)
    # 4. 숫자 → N (id=123, id=999 같은 변동값 통일)
    text = re.sub(r"\d+", "N", text)
    # 5. 연속 공백 정리
    text = re.sub(r"\s+", " ", text).strip()

    return text


def compute_cluster_key(raw_event: dict) -> str:
    """정규화된 공격 로그의 SHA256 앞 16자로 클러스터 키 생성."""
    normalized = normalize_attack_log(raw_event)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"aegis:cluster:{digest}"


# ============================================================
# [Aegis-3 SOAR] 오탐지 감지 — 운영자 unblock 추적
# blacklist에 등록됐던 IP가 운영자에 의해 해제되면 오탐지 의심 카운터를 증가시키고,
# 임계값을 넘으면 의심 IP Set에 추가하여 운영자가 조회할 수 있게 한다.
# ============================================================


def record_false_positive(ip: str) -> dict:
    """
    운영자가 blacklist IP를 해제할 때 호출되는 함수.
    Slack 봇의 unblock 명령에서 이 함수를 부르도록 협의 필요.
    """
    if not ip or ip == "unknown":
        return {"ok": False, "reason": "invalid_ip"}

    try:
        # 해당 IP의 오탐지 의심 카운터 증가
        fp_count = redis_client.incr(f"aegis:false_positive:{ip}")
        # 전체 통계
        redis_client.incr("aegis:stats:false_positive_total")
        # TTL 30일 — 그 이후엔 카운터 자동 만료
        redis_client.expire(f"aegis:false_positive:{ip}", 60 * 60 * 24 * 30)

        # 임계값 초과 시 의심 IP Set에 추가
        is_suspect = False
        if fp_count >= FP_THRESHOLD:
            redis_client.sadd("aegis:suspect_fp_ips", ip)
            is_suspect = True
            print(f"[Worker] ⚠️ 오탐지 의심 IP 등록: {ip} (해제 횟수: {fp_count}, 임계값: {FP_THRESHOLD})")
        else:
            print(f"[Worker] 📝 unblock 기록: {ip} (해제 횟수: {fp_count}/{FP_THRESHOLD})")

        return {
            "ok": True,
            "ip": ip,
            "fp_count": fp_count,
            "threshold": FP_THRESHOLD,
            "is_suspect": is_suspect,
        }
    except Exception as redis_err:
        print(f"[Worker] ⚠️ 오탐지 기록 실패: {redis_err}")
        return {"ok": False, "reason": str(redis_err)}


def get_suspect_fp_ips() -> list:
    """오탐지 의심 IP 목록 조회. Slack 봇 또는 운영자가 호출."""
    try:
        ips = redis_client.smembers("aegis:suspect_fp_ips")
        return list(ips) if ips else []
    except Exception as redis_err:
        print(f"[Worker] ⚠️ 의심 IP 조회 실패: {redis_err}")
        return []


def normalize_redis_log(log_data):
    """
    Redis에서 꺼낸 이벤트를 dict로 변환한다.

    Redis rpop 결과는 str 또는 bytes일 수 있고,
    Webhook 테스트에서는 dict로 들어올 수도 있어서 모두 처리한다.
    """
    if isinstance(log_data, bytes):
        log_data = log_data.decode("utf-8")

    if isinstance(log_data, str):
        return json.loads(log_data)

    if isinstance(log_data, dict):
        return log_data

    raise ValueError(f"Unsupported log_data type: {type(log_data)}")


def _build_mongo_uri():
    """
    MONGO_USER / MONGO_PASSWORD 가 따로 주어지면 패스워드를 URL-encode 해서 URI 를 조립한다.
    docker-compose 가 ${VAR} 치환 시 URL-escape 하지 않기 때문에, 패스워드에 @ : / ? # 등이
    들어있으면 MONGO_URI 그대로는 pymongo 가 거절한다. 별도 컴포넌트를 받아 안전하게 만든다.
    """
    user = os.getenv("MONGO_USER")
    password = os.getenv("MONGO_PASSWORD")
    if user and password:
        host = os.getenv("MONGO_HOST", "mongodb")
        port = os.getenv("MONGO_PORT", "27017")
        db_name = os.getenv("MONGO_DB_NAME", "aegis_logs")
        auth_source = os.getenv("MONGO_AUTH_SOURCE", "admin")
        return (
            f"mongodb://{quote_plus(user)}:{quote_plus(password)}"
            f"@{host}:{port}/{db_name}?authSource={auth_source}"
        )
    return MONGO_URI


def get_mongo_collection(name=None):
    """
    MongoDB collection 객체를 반환한다. name 미지정 시 보안 로그 컬렉션.
    """
    client = MongoClient(_build_mongo_uri())
    db = client[MONGO_DB_NAME]
    return db[name or MONGO_COLLECTION_NAME]


def _log_ai_rule_event(event: dict) -> None:
    """AI 룰 실험 로그 1건 저장. 실패해도 본 파이프라인에는 영향 없음."""
    event.setdefault("ts", datetime.utcnow().isoformat() + "Z")
    event.setdefault("source", "worker")
    try:
        get_mongo_collection(AI_RULE_EVENTS_COLLECTION).insert_one(event)
    except Exception as log_err:
        print(f"[Worker] ⚠️ AI 룰 이벤트 저장 실패(무시): {log_err}")


def drain_ai_rule_events(batch_size: int = 500) -> int:
    """sidecar 가 큐에 쌓은 AI 룰 이벤트를 MongoDB 로 옮긴다. 저장 실패 시 큐로 되돌림."""
    raws = []
    while len(raws) < batch_size:
        raw = redis_client.rpop(AI_RULE_EVENT_QUEUE)
        if not raw:
            break
        raws.append(raw)
    docs = []
    for r in raws:
        try:
            docs.append(json.loads(r))
        except ValueError:
            print(f"[Worker] ⚠️ 깨진 AI 룰 이벤트 버림: {r[:200]}")
    if not docs:
        return 0
    try:
        get_mongo_collection(AI_RULE_EVENTS_COLLECTION).insert_many(docs)
    except Exception as mongo_err:
        # RPOP 한 쪽(꼬리)으로 되돌려 다음 주기에 재시도
        redis_client.rpush(AI_RULE_EVENT_QUEUE, *[json.dumps(d) for d in reversed(docs)])
        print(f"[Worker] ⚠️ AI 룰 이벤트 적재 실패, 큐로 복원: {mongo_err}")
        return 0
    return len(docs)


def build_mongo_document(raw_event, analyzer_result):
    """
    MongoDB에 저장할 최종 로그 문서를 만든다.

    raw_event:
    - Proxy가 Redis에 넣은 원본 이벤트

    security_analysis:
    - Risk Score Engine이 계산한 결과
    """
    detection_result = analyzer_result.get("detection_result", {})
    alert_event = analyzer_result.get("alert_event")

    risk_score = detection_result.get("risk_score")
    level = detection_result.get("level")
    alert = detection_result.get("alert")
    reasons = detection_result.get("reasons", [])
    action = detection_result.get("action_on_match", raw_event.get("action_on_match"))

    # [확정 악성 격상] Coraza 차단(SQLi/XSS 등)·허니팟·block 액션은 '이미 확정된 공격'이다.
    # 그런데 Risk Score 엔진 detector 는 SQLi/XSS 를 점수화하지 않아(그건 WAF 몫)
    # 차단된 공격이 LOW 로 표시되는 모순이 생긴다. → 휴리스틱 점수와 무관하게 CRITICAL 로 격상.
    ev_type = str(raw_event.get("event_type") or "").lower()
    action_l = str(action or "").lower()
    if ev_type in ("waf_blocked", "blocked_request", "honeypot_hit") or action_l in ("block", "honeypot"):
        risk_score = 100
        level = "CRITICAL"
        alert = True
        if not reasons:
            reasons = [f"확정 악성 이벤트({ev_type or action_l}) — 자동 CRITICAL 격상"]

    return {
        "event_id": raw_event.get("event_id"),
        "trace_id": raw_event.get("trace_id"),

        "raw_event": raw_event,

        "security_analysis": {
            "status": "analyzed",
            "risk_score": risk_score,
            "level": level,
            "alert": alert,
            "rule_hits": detection_result.get("rule_hits", []),
            "reasons": reasons,
            "analysis_profile": detection_result.get(
                "analysis_profile",
                raw_event.get("analysis_profile")
            ),
            "action_on_match": action,
        },

        # 지금 단계에서는 LLM/대응 호출은 보류.
        # 나중에 HIGH/CRITICAL일 때 analyzer.js /api/v1/report로 넘기면 됨.
        "llm": {
            "sent": False,
            "reason": "LLM/SOAR response is deferred"
        },

        "alert_event": alert_event,

        "created_at": datetime.utcnow().isoformat() + "Z"
    }


def _build_coraza_rule(rule: dict) -> str:
    """AI가 반환한 dict를 Coraza SecRule 한 줄로 직렬화"""
    regex = rule.get("regex", "").replace('"', '\\"')
    name = rule.get("rule_name", "AI_GENERATED").replace('"', '\\"')
    # 룰 ID 충돌 방지:
    # - 900000~999999 는 OWASP CRS 가 점유 (REQUEST/RESPONSE 9xx 시리즈)
    # - 100~100090 은 aegis3-custom-rules.conf 가 사용
    # AI 룰은 32-bit 정수 한계(약 21억) 안의 2,000,000,000~2,099,999,999 범위로 격리.
    # ms 정밀도 + 1억 modulo → 약 11.5년 cycle, 같은 ms 동시 발화 외엔 자체 충돌 없음.
    rule_id = 2_000_000_000 + (int(time.time() * 1000) % 100_000_000)
    return (
        f'SecRule REQUEST_URI|ARGS|REQUEST_BODY "@rx {regex}" '
        f'"id:{rule_id},phase:2,deny,status:403,msg:\'{name}\',log"'
    )


def _inject_rule_to_nginx(rule: dict):
    """생성된 WAF 룰을 Nginx 사이드카로 전송. 성공 시 rule_id, 실패 시 None."""
    try:
        rule_str = _build_coraza_rule(rule)
        resp = requests.post(
            NGINX_SIDECAR_URL,
            json={"rule": rule_str},
            timeout=5,
        )
        print(f"[Worker] WAF 룰 주입 응답: {resp.status_code} - {resp.text[:200]}")
        if resp.ok:
            return int(re.search(r"id:(\d+)", rule_str).group(1))
    except Exception as inj_err:
        print(f"[Error] Nginx 사이드카 룰 주입 실패: {inj_err}")
    return None


# ============================================================
# 자동 재무장 — 공격 지문(정규화 패턴 해시, compute_cluster_key 와 동일) → 그 공격으로
# 만든 rule_id 장부. 같은 지문의 공격이 다시 오면 LLM 대신 보관된 룰을 재무장한다.
# 재무장된 룰은 shadow(관찰)로 돌아가 재검증부터 받는다.
# ============================================================

RULE_FP_PREFIX = "aegis:rule-fp:"
RULE_FP_TTL_SECONDS = int(os.getenv("RULE_FP_TTL_SECONDS", str(30 * 86400)))  # 30일


def _remember_rule_fingerprint(fingerprint: str, rule_id: int) -> None:
    try:
        redis_client.setex(RULE_FP_PREFIX + fingerprint, RULE_FP_TTL_SECONDS, rule_id)
    except Exception as redis_err:
        print(f"[Worker] ⚠️ 룰 지문 장부 저장 실패: {redis_err}")


def _try_auto_rearm(fingerprint: str):
    """
    장부에 룰이 있으면 사이드카 재무장 호출.
    - 200 rearmed: 보관본을 shadow 로 되살림
    - 409 already_active: 룰이 이미 관찰/차단 중 → 새 룰 불필요
    그 외(장부 없음, 보관본 없음 404, Redis/사이드카 장애) → None = 기존대로 LLM 진행.
    """
    try:
        rule_id = redis_client.get(RULE_FP_PREFIX + fingerprint)
    except Exception as redis_err:
        print(f"[Worker] ⚠️ 룰 지문 장부 조회 실패: {redis_err} — LLM 진행")
        return None
    if not rule_id:
        return None

    rearm_url = NGINX_SIDECAR_URL.rsplit("/", 1)[0] + f"/rearm/{rule_id}"
    try:
        resp = requests.post(rearm_url, timeout=5)
    except Exception as req_err:
        print(f"[Worker] ⚠️ 재무장 호출 실패: {req_err} — LLM 진행")
        return None
    print(f"[Worker] 재무장 응답(rule {rule_id}): {resp.status_code} - {resp.text[:200]}")
    if resp.status_code == 200:
        return {"result": "rearmed", "rule_id": int(rule_id)}
    if resp.status_code == 409:
        return {"result": "already_active", "rule_id": int(rule_id)}
    return None


def _blacklist_ip(blacklist_key, ip) -> None:
    """고위험 IP 24h 블랙리스트 — Proxy 1차 차단 미들웨어가 다음 요청을 즉시 끊는다."""
    if not blacklist_key:
        return
    try:
        redis_client.setex(blacklist_key, 86400, "1")
        print(f"[Worker] 🔒 IP {ip} blacklist 등록 (TTL 24h)")
    except Exception as redis_err:
        print(f"[Worker] ⚠️ Redis SETEX 실패: {redis_err}")


def _report_to_analyzer(ip: str, attack_type: str) -> None:
    """
    고위험 이벤트를 analyzer(/api/v1/report)로 보고.
    analyzer 가 Cloudflare 차단 + Slack 알림 + Email 보고를 수행한다.
    실패해도 본 파이프라인(저장/룰생성)에는 영향 없도록 예외를 삼킨다.
    """
    try:
        resp = requests.post(
            ANALYZER_REPORT_URL,
            json={"ip": ip, "type": attack_type},
            timeout=5,
        )
        print(f"[Worker] analyzer 보고 응답: {resp.status_code} - {resp.text[:200]}")
    except Exception as rep_err:
        print(f"[Error] analyzer 보고 실패(무시): {rep_err}")


@celery_app.task(bind=True, max_retries=3)
def process_security_log(self, log_data):
    """
    Redis에서 꺼낸 단일 이벤트 로그를 처리하는 Task.

    Redis 이벤트 → Risk Score Engine /analyze → MongoDB 저장
                → (risk_score ≥ AI_RULE_THRESHOLD) AI WAF 룰 생성 → Nginx 사이드카 주입
    """
    try:
        raw_event = normalize_redis_log(log_data)
        print(f"[Worker] Redis 이벤트 처리 시작: {raw_event}")

        # ------------------------------------------------------------
        # 1. Risk Score Engine으로 분석 요청
        # ------------------------------------------------------------
        try:
            response = requests.post(
                RISK_ANALYZER_URL,
                json=raw_event,
                timeout=5
            )
            response.raise_for_status()
            analyzer_result = response.json()

            print(
                "[Worker] Risk Score 응답 수신: "
                f"{response.status_code} - {analyzer_result}"
            )

        except Exception as req_err:
            print(f"[Error] Risk Score Engine 호출 실패: {req_err}")
            raise req_err

        # ------------------------------------------------------------
        # 2. MongoDB에 최종 로그 저장
        # ------------------------------------------------------------
        try:
            mongo_doc = build_mongo_document(
                raw_event=raw_event,
                analyzer_result=analyzer_result
            )

            collection = get_mongo_collection()
            insert_result = collection.insert_one(mongo_doc)

            print(f"[Worker] MongoDB 저장 완료: inserted_id={insert_result.inserted_id}")

        except Exception as mongo_err:
            print(f"[Error] MongoDB 저장 실패: {mongo_err}")
            raise mongo_err

        # ------------------------------------------------------------
        # 3. 고위험 시 AI WAF 룰 생성 → Nginx 사이드카로 주입
        # ------------------------------------------------------------
        detection_result = analyzer_result.get("detection_result", {})
        risk_score = int(detection_result.get("risk_score") or 0)
        if risk_score >= AI_RULE_THRESHOLD:
            # ──────────────────────────────────────────────────────────
            # [Aegis-3 SOAR] IP 평판 — 작업 6-A
            # LLM 호출 전 블랙리스트 체크: 24시간 내 이미 악성 판정된 IP면
            # LLM 재호출 없이 즉시 스킵 (비용·할당량 절감)
            # Redis 장애 시 fail-open — 정상 분석은 계속 진행
            # ──────────────────────────────────────────────────────────
            ip = raw_event.get("ip")
            blacklist_key = f"aegis:blacklist:{ip}" if ip and ip != "unknown" else None

            # ── analyzer 통합 대응(CF 차단/Slack/Email) 트리거 ──
            # blacklist/cluster 캐시로 LLM 을 스킵하더라도 알림은 보내도록,
            # 조기 return 들보다 먼저 이 위치에서 보고한다.
            _alert_level = detection_result.get("level") or "HIGH"
            _alert_hits = detection_result.get("rule_hits") or []
            _attack_type = f"{_alert_level} (risk {risk_score})"
            if _alert_hits:
                _attack_type += " / " + ", ".join(str(h) for h in _alert_hits)
            _report_to_analyzer(ip or "unknown", _attack_type)

            if blacklist_key:
                try:
                    if redis_client.exists(blacklist_key):
                        try:
                            redis_client.incr("aegis:stats:llm_skipped")
                        except Exception:
                            pass
                        print(f"[Worker] 🛑 IP {ip} blacklist hit — LLM 호출 skip")
                        return {
                            "status": "success",
                            "event_id": raw_event.get("event_id"),
                            "risk_score": risk_score,
                            "level": detection_result.get("level"),
                            "llm_skipped": True,
                            "reason": "ip_blacklisted",
                        }
                except Exception as redis_err:
                    print(f"[Worker] ⚠️ Redis EXISTS 실패: {redis_err} — fail-open으로 LLM 진행")

            # ──────────────────────────────────────────────────────────
            # [Aegis-3 SOAR] 작업 7 — 공격 클러스터 캐시 체크
            # 정규화된 패턴이 5분 내 이미 처리됐으면 LLM 재호출 없이 결과 재사용
            # Redis 장애 시 fail-open
            # ──────────────────────────────────────────────────────────
            cluster_key = compute_cluster_key(raw_event)
            try:
                cached_rule_name = redis_client.get(cluster_key)
                if cached_rule_name:
                    try:
                        redis_client.incr("aegis:stats:cluster_skipped")
                    except Exception:
                        pass
                    print(f"[Worker] ♻️ 클러스터 캐시 hit ({cluster_key}) — LLM 호출 skip, 기존 룰 재사용: {cached_rule_name}")
                    return {
                        "status": "success",
                        "event_id": raw_event.get("event_id"),
                        "risk_score": risk_score,
                        "level": detection_result.get("level"),
                        "llm_skipped": True,
                        "reason": "cluster_cache_hit",
                        "cached_rule": cached_rule_name,
                    }
            except Exception as redis_err:
                print(f"[Worker] ⚠️ 클러스터 캐시 조회 실패: {redis_err} — fail-open으로 LLM 진행")

            # ──────────────────────────────────────────────────────────
            # 자동 재무장 — 같은 지문으로 만든 룰이 있으면 LLM 대신 재무장
            # ──────────────────────────────────────────────────────────
            fingerprint = cluster_key.rsplit(":", 1)[1]
            rearm = _try_auto_rearm(fingerprint)
            if rearm:
                _blacklist_ip(blacklist_key, ip)
                try:
                    redis_client.incr("aegis:stats:rearm_skipped")
                except Exception:
                    pass
                print(f"[Worker] 🔁 자동 재무장 ({rearm['result']}, rule {rearm['rule_id']}) — LLM 호출 skip")
                _log_ai_rule_event({
                    "type": "auto_rearm",
                    **rearm,  # result, rule_id
                    "fingerprint": fingerprint,
                    "event_id": raw_event.get("event_id"),
                    "ip": ip,
                    "method": raw_event.get("method"),
                    "path": raw_event.get("path"),
                    "risk_score": risk_score,
                })
                return {
                    "status": "success",
                    "event_id": raw_event.get("event_id"),
                    "risk_score": risk_score,
                    "level": detection_result.get("level"),
                    "llm_skipped": True,
                    "reason": rearm["result"],
                    "rule_id": rearm["rule_id"],
                }

            # LLM 호출 (기존 로직)
            print(f"[Worker] 🧠 risk_score={risk_score} ≥ {AI_RULE_THRESHOLD}, AI 룰 생성 시작")
            gen_meta = {}
            t0 = time.time()
            ai_rule = generate_waf_rule_with_feedback(raw_event, meta=gen_meta)
            llm_latency_ms = int((time.time() - t0) * 1000)

            # ──────────────────────────────────────────────────────────
            # [Aegis-3 SOAR] 작업 7 — 클러스터 캐시 저장
            # 다음 5분 안에 같은 패턴이 다시 오면 LLM 재호출 회피
            # ──────────────────────────────────────────────────────────
            if ai_rule and ai_rule.get("rule_name"):
                try:
                    redis_client.setex(cluster_key, CLUSTER_TTL_SECONDS, ai_rule.get("rule_name"))
                    print(f"[Worker] 📌 클러스터 캐시 저장 ({cluster_key}, TTL {CLUSTER_TTL_SECONDS}s): {ai_rule.get('rule_name')}")
                except Exception as redis_err:
                    print(f"[Worker] ⚠️ 클러스터 캐시 저장 실패: {redis_err}")

            # LLM 호출 후 IP를 24h 블랙리스트 등록 (성공/실패 모두)
            _blacklist_ip(blacklist_key, ip)

            rule_id = None
            if ai_rule and ai_rule.get("regex"):
                print(f"[Worker] ✅ AI 룰 생성됨: {ai_rule.get('rule_name')} (confidence={ai_rule.get('confidence_score')})")
                rule_id = _inject_rule_to_nginx(ai_rule)
                if rule_id:
                    _remember_rule_fingerprint(fingerprint, rule_id)
            else:
                print(f"[Worker] ⚠️ AI 룰 생성 실패(반환 None) — 주입 건너뜀")

            _log_ai_rule_event({
                "type": "generated" if ai_rule else "generation_failed",
                "rule_id": rule_id,  # sidecar 이벤트와 조인 키. 주입 실패 시 None
                "rule_name": (ai_rule or {}).get("rule_name"),
                "regex": (ai_rule or {}).get("regex"),
                "confidence_score": (ai_rule or {}).get("confidence_score"),
                "llm_latency_ms": llm_latency_ms,
                **gen_meta,  # model, attempts, errors
                "fingerprint": fingerprint,
                "event_id": raw_event.get("event_id"),
                "ip": ip,
                "method": raw_event.get("method"),
                "path": raw_event.get("path"),
                "risk_score": risk_score,
            })

        print("[Worker] 로그 처리 완료")

        return {
            "status": "success",
            "event_id": raw_event.get("event_id"),
            "risk_score": risk_score,
            "level": detection_result.get("level"),
        }

    except Exception as exc:
        print(f"[Error] 로그 처리 실패: {exc}")
        raise self.retry(exc=exc, countdown=5)


@celery_app.task
def consume_logs_from_redis_queue():
    """
    Redis List에 쌓인 Proxy 이벤트를 꺼내 Celery Task로 넘긴다.

    Proxy:
    LPUSH aegis:security-events

    Worker:
    RPOP aegis:security-events

    이렇게 하면 오래된 이벤트부터 처리된다.
    """
    queue_name = REDIS_QUEUE_NAME
    batch_size = 100

    logs_processed = 0

    while logs_processed < batch_size:
        log_raw = redis_client.rpop(queue_name)

        if not log_raw:
            break

        process_security_log.delay(log_raw)
        logs_processed += 1

    try:
        drain_ai_rule_events()
    except Exception as drain_err:
        print(f"[Worker] ⚠️ AI 룰 이벤트 drain 실패(무시): {drain_err}")

    message = f"{logs_processed}개의 로그를 Redis 큐에서 꺼내 처리 작업에 할당했습니다."
    print(f"[Worker] {message}")

    return message