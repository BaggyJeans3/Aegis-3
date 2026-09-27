#!/usr/bin/env python3
"""
위험도 점수 ↔ AI 룰 생성 정합 점검 (Gemini 호출 없음)

대표 상황(정상·공격)을 위험도 엔진 /analyze 에 직접 보내 점수를 받고, 워커 규칙대로
"AI 룰 생성(= IP 차단목록 등록)" 여부를 운영 임계값(80)과 시연 임계값(30)으로 판정한다.
워커 규칙: risk_score ≥ AI_RULE_THRESHOLD 또는 event_type == honeypot_hit (tasks.py)

  python scripts/experiment/threshold_check.py [--url http://localhost:5001/analyze]

SOAR 탐지기·임계값이 바뀌면 다시 돌려 전후를 비교한다. 결과: scripts/experiment/results/threshold-<시각>/
엔진은 IP·세션별 시간창 상태를 가지므로 상황마다 새 IP·세션을 쓴다.
"""
import argparse
import json
import urllib.request
from datetime import datetime
from itertools import count
from pathlib import Path

HERE = Path(__file__).resolve().parent
THRESHOLDS = (80, 30)  # 운영, 시연
_ip = count(1)


def ev(path, *, query="", status=200, event_type="request", profile="full", headers=None, **extra):
    return {"path": path, "query": query, "method": "GET", "body": "", "status_code": status,
            "event_type": event_type, "analysis_profile": profile,
            "headers": headers or {"user-agent": "Mozilla/5.0"}, **extra}


# (이름, 정답, 설명, 이벤트 목록) — 연속 이벤트는 마지막 이벤트의 점수로 판정
CASES = [
    ("normal_browse", "normal", "상품 목록 조회 1회",
     [ev("/shop/products", query="page=2")]),
    ("normal_private_xff", "normal", "정상 요청, 헤더에 사설 IP (로컬·컨테이너 환경)",
     [ev("/shop/products", query="page=2",
         headers={"user-agent": "Mozilla/5.0", "x-forwarded-for": "172.18.0.5, 127.0.0.1"})]),
    ("normal_host_localhost", "normal", "정상 요청, Host 가 localhost",
     [ev("/shop/cart", headers={"user-agent": "Mozilla/5.0", "host": "localhost:8080"})]),
    ("normal_heavy_user_120", "normal", "정상 사용자 60초에 120회 요청 (부하 테스트 수준)",
     [ev("/shop/products", query=f"page={i}", event_type="access_event", profile="rate_only") for i in range(120)]),
    ("normal_login_fail_3", "normal", "로그인 3회 실패",
     [ev("/api/v1/auth/login", status=401) for _ in range(3)]),
    ("attack_honeypot", "attack", "허니팟 경로 접근 (honeypot_hit)",
     [ev("/shop/debug/session-dump", event_type="honeypot_hit")]),
    ("attack_admin_path", "attack", "관리자 경로 접근",
     [ev("/admin/login")]),
    ("attack_env_file", "attack", "/.env 접근",
     [ev("/.env")]),
    ("attack_path_traversal", "attack", "경로 조작 (../../etc/passwd)",
     [ev("/download", query="file=../../etc/passwd")]),
    ("attack_ssrf", "attack", "SSRF (클라우드 메타데이터 주소)",
     [ev("/fetch", query="url=http://169.254.169.254/latest/meta-data")]),
    ("attack_cmd_injection", "attack", "명령어 삽입",
     [ev("/ping", query="host=1;cat /etc/passwd")]),
    ("attack_scan_30", "attack", "60초에 없는 경로 30개 탐색",
     [ev(f"/shop/probe-{i}", status=404) for i in range(30)]),
    ("attack_bola_10", "attack", "남의 객체 ID 10개 연속 조회",
     [ev(f"/api/v1/users/{i}", user_id="1", target_user_id=str(i)) for i in range(2, 12)]),
    ("attack_login_bruteforce_10", "attack", "로그인 10회 실패",
     [ev("/api/v1/auth/login", status=401) for _ in range(10)]),
    ("attack_flood_200", "attack", "60초에 200회 요청",
     [ev("/shop/products", event_type="access_event", profile="rate_only") for _ in range(200)]),
]


def analyze(url, event):
    req = urllib.request.Request(url, data=json.dumps(event).encode(), headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=10).read())["detection_result"]


def run_case(url, name, events):
    ip, session = f"203.0.113.{next(_ip)}", f"thcheck-{name}"
    result = None
    for i, e in enumerate(events):
        result = analyze(url, {**e, "event_id": f"thcheck-{name}-{i}", "trace_id": "t",
                               "ip": ip, "session_id": session})
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default="http://localhost:5001/analyze")
    a = p.parse_args()

    rows = []
    for name, truth, desc, events in CASES:
        r = run_case(a.url, name, events)
        score = int(r.get("risk_score") or 0)
        honeypot = events[-1]["event_type"] == "honeypot_hit"
        trig = {t: score >= t or honeypot for t in THRESHOLDS}
        # 정답과 어긋나는 판정: 공격인데 룰이 안 생김 / 정상인데 룰이 생기고 IP 차단
        flags = [f"{'놓침' if truth == 'attack' else '오탐'}@{t}" for t in THRESHOLDS
                 if trig[t] != (truth == "attack")]
        rows.append({"case": name, "truth": truth, "desc": desc, "score": score, "level": r.get("level"),
                     "rule_hits": r.get("rule_hits", []), "ai_rule_at": trig, "mismatch": flags})

    out = HERE / "results" / f"threshold-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "threshold.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    lines = ["| 상황 | 정답 | 점수 | 탐지 규칙 | AI 룰·IP 차단 (운영 80) | (시연 30) | 어긋남 |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    ox = lambda b: "O" if b else "-"
    for r in rows:
        lines.append(f"| {r['desc']} | {r['truth']} | {r['score']} | {', '.join(r['rule_hits']) or '-'} | "
                     f"{ox(r['ai_rule_at'][80])} | {ox(r['ai_rule_at'][30])} | {', '.join(r['mismatch']) or '-'} |")
    md = "\n".join(lines) + "\n"
    (out / "threshold.md").write_text(md, encoding="utf-8")
    print(md + f"\n결과: {out}")


if __name__ == "__main__":
    main()
