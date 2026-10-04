#!/usr/bin/env python3
"""
k6 부하 테스트 대비 detector 임계값 사전 점검 시뮬레이터
=========================================================

scripts/aegis3_load_test.js 의 각 시나리오가 '실제로 Redis 큐에 만들어낼 이벤트 흐름'을 재현해
Risk Score Engine(analyze_log)에 그대로 흘려보내고, 다음을 집계한다.

  - 등급(LOW/SUSPICIOUS/HIGH/CRITICAL) 분포  → 대시보드에 어떻게 찍힐지
  - AI_RULE_THRESHOLD 이상 이벤트 수        → worker 가 analyzer(/api/v1/report: CF 차단+Slack+Email)를
                                               부르는 횟수. LLM 은 첫 1회 후 IP 블랙리스트로 skip 되지만
                                               report 는 매 이벤트마다 호출된다.
  - 최초 트리거 시점                         → 이 시점 이후 k6 IP 가 블랙리스트 → proxy 403

[이벤트 흐름 가정 — 정적 분석 기반, EC2 에서 확인 필요]
  * k6 는 단일 호스트에서 실행 → 모든 VU 가 같은 client IP.
  * 정상 요청(/, /index.html, /ping) → proxy catch-all(/*) → access_event(rate_only)
  * 공격 요청 중 큐에 이벤트가 남는 것은 CRS phase 2 에서 949110 이 뜨는 SQLi, XSS 뿐.
      - /api/v1/admin(110001), sqlmap UA(160010), /actuator(130001) : 커스텀 룰 phase 1 deny
      - POST /submit {"role":"admin"}(150002) : 커스텀 룰 phase 2 deny, CRS 이상점수 0
      → 949110/959100 이 없으므로 sidecar 가 큐에 넣지 않음(BLOCK_SIGNAL_RULE_IDS).
  * 요청률은 VU / (think time 평균 0.35s + 응답시간) 으로 근사한다(--latency 로 조정).

사용:
  python3 scripts/soar_bench/k6_threshold_sim.py                  # 전 시나리오, 임계값 80·30
  python3 scripts/soar_bench/k6_threshold_sim.py --scenario mixed --latency 0.05
  NORMAL_P95_PER_MINUTE=200 python3 scripts/soar_bench/k6_threshold_sim.py   # 튜닝값 미리 보기
"""

import argparse
import os
import random
import sys
from collections import Counter
from datetime import datetime, timedelta

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_ROOT)

from soar.risk_score_engine.app import analyze_log  # noqa: E402
from soar.risk_score_engine.state import reset_all_state  # noqa: E402

THINK_TIME_AVG = 0.35  # k6: sleep(Math.random() * 0.5 + 0.1)

# aegis3_load_test.js 의 profiles 와 동일
PROFILES = {
    "normal": [(30, 0, 20), (60, 20, 50), (120, 50, 100), (30, 100, 0)],
    "attack": [(30, 0, 30), (120, 30, 80), (30, 80, 0)],
    "mixed": [(30, 0, 30), (120, 30, 100), (60, 100, 100), (30, 100, 0)],
    "soak": [(1800, 30, 30)],
}

NORMAL_PATHS = ["/", "/index.html", "/ping"]
# attackRequests 6종 중 큐에 도달하는 것 (SQLi, XSS). 나머지 4종은 None(이벤트 없음)
ATTACK_EVENTS = [
    None,  # /api/v1/admin
    None,  # sqlmap UA
    None,  # /actuator
    ("/api/v1/users", "id=1%27%20OR%20%271%27%3D%271"),
    ("/api/v1/search", "q=%3Cscript%3Ealert(1)%3C/script%3E"),
    None,  # POST /submit role=admin
]


def vus_at(stages, t):
    elapsed = 0
    for dur, start, end in stages:
        if t < elapsed + dur:
            return start + (end - start) * (t - elapsed) / dur
        elapsed += dur
    return 0


def build_stream(scenario, latency, client_ip, rng, max_seconds=None, spread_ips=0):
    """(offset_seconds, event) 스트림 생성"""
    stages = PROFILES[scenario]
    total = sum(d for d, _, _ in stages)
    if max_seconds:
        total = min(total, max_seconds)
    per_vu_rps = 1.0 / (THINK_TIME_AVG + latency)
    t = 0.0
    step = 0.1
    events = []
    carry = 0.0
    while t < total:
        rps = vus_at(stages, t) * per_vu_rps
        carry += rps * step
        n = int(carry)
        carry -= n
        for i in range(n):
            ts = t + i * step / max(n, 1)
            if scenario in ("normal", "soak"):
                is_attack = False
            elif scenario == "attack":
                is_attack = True
            else:
                is_attack = rng.random() >= 0.8
            if not is_attack:
                ev = {
                    "event_type": "access_event", "analysis_profile": "rate_only",
                    "path": rng.choice(NORMAL_PATHS), "status_code": 0, "action_on_match": "proxy",
                    "headers": {"user-agent": "Mozilla/5.0", "x-forwarded-for": f"{client_ip}, 127.0.0.1"},
                }
            else:
                target = rng.choice(ATTACK_EVENTS)
                if target is None:
                    continue  # Coraza 커스텀 룰 차단 → 큐 이벤트 없음
                path, query = target
                ev = {
                    "event_type": "waf_blocked", "analysis_profile": "full", "path": path, "query": query,
                    "headers": {}, "status_code": 403, "action_on_match": "block",
                }
            if spread_ips and ev["event_type"] == "access_event":
                # k6 SPREAD_IPS=N: X-Forwarded-For 를 N개 IP 로 분산 (proxy 는 내부(사설/루프백) 요청일 때만 XFF 첫 값을 client IP 로 씀)
                n_ip = rng.randrange(spread_ips)
                ev["ip"] = f"198.18.{n_ip // 256}.{n_ip % 256}"
            else:
                ev["ip"] = client_ip
            ev["session_id"] = "unknown"
            events.append((ts, ev))
        t += step
    return events


def simulate(scenario, thresholds, latency, max_seconds=None, spread_ips=0):
    reset_all_state()
    rng = random.Random(7)
    base = datetime(2026, 9, 28, 14, 0, 0)
    stream = build_stream(scenario, latency, "172.18.0.1", rng, max_seconds, spread_ips)

    levels = Counter()
    hits = Counter()
    over = {th: 0 for th in thresholds}
    first = {th: None for th in thresholds}
    max_score = 0
    for offset, ev in stream:
        ev["timestamp"] = (base + timedelta(seconds=offset)).isoformat() + "Z"
        r = analyze_log(ev)
        score = r["risk_score"]
        max_score = max(max_score, score)
        levels[r["level"]] += 1
        for h in r["rule_hits"]:
            hits[h] += 1
        for th in thresholds:
            if score >= th:
                over[th] += 1
                if first[th] is None:
                    first[th] = offset
    return {
        "scenario": scenario, "events": len(stream), "levels": levels, "hits": hits,
        "over": over, "first": first, "max_score": max_score,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", choices=list(PROFILES) + ["all"], default="all")
    ap.add_argument("--thresholds", default="80,30", help="비교할 AI_RULE_THRESHOLD 값들 (운영 80, 시연 30)")
    ap.add_argument("--latency", type=float, default=0.05, help="평균 응답시간(초). 요청률 근사에 사용")
    ap.add_argument("--spread-ips", type=int, default=0, help="k6 SPREAD_IPS 옵션 재현 (정상 요청 XFF 를 N개 IP 로 분산)")
    ap.add_argument("--soak-seconds", type=int, default=300, help="soak 는 30분 전체 대신 앞부분만 (시간 절약)")
    args = ap.parse_args()

    thresholds = [int(x) for x in args.thresholds.split(",")]
    scenarios = list(PROFILES) if args.scenario == "all" else [args.scenario]

    print(f"요청률 근사: VU당 {1 / (THINK_TIME_AVG + args.latency):.2f} req/s (think {THINK_TIME_AVG}s + 응답 {args.latency}s)")
    print("※ 이벤트 흐름 가정은 파일 상단 docstring 참고 (Coraza 커스텀 룰 차단분은 큐 이벤트 없음)\n")

    for sc in scenarios:
        r = simulate(sc, thresholds, args.latency, args.soak_seconds if sc == "soak" else None, args.spread_ips)
        total = r["events"] or 1
        lv = r["levels"]
        print(f"[{sc}] 큐 이벤트 {r['events']:,}건  최고점 {r['max_score']}")
        print("   등급 분포: " + "  ".join(
            f"{k} {lv.get(k, 0):,} ({lv.get(k, 0) * 100 / total:.0f}%)" for k in ("LOW", "SUSPICIOUS", "HIGH", "CRITICAL")))
        print("   룰 적중  : " + (", ".join(f"{k}×{v:,}" for k, v in r["hits"].most_common()) or "없음"))
        for th in thresholds:
            first = r["first"][th]
            when = f"{first:.0f}s 시점 최초" if first is not None else "-"
            flag = "  ⚠ report 폭주 + k6 IP 블랙리스트(이후 proxy 403)" if r["over"][th] else ""
            print(f"   AI_RULE_THRESHOLD={th:>3}: analyzer report 호출 {r['over'][th]:,}회 ({when}){flag}")
        print()


if __name__ == "__main__":
    main()
