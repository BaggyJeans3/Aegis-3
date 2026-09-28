# =========================
# app.py
# Flask API 서버 / Risk Score 계산 / Alert Event 생성
# =========================

from flask import Flask, request, jsonify
import json
import os
import threading
import time

from soar.risk_score_engine.config import (
    ALERT_THRESHOLD,
    SLOW_WINDOW_SECONDS,
    STATE_PURGE_EVERY,
)
from soar.risk_score_engine.utils import parse_time, get_level, safe_int
from soar.risk_score_engine.detectors import get_detectors_by_profile
from soar.risk_score_engine.state import STATE_LOCK, ALL_STATE_STORES, purge_idle_keys

app = Flask(__name__)

# alert_events.jsonl 저장 경로 (기본값 = 기존과 동일하게 작업 디렉터리)
ALERT_EVENTS_PATH = os.getenv("ALERT_EVENTS_PATH", "alert_events.jsonl")
_alert_file_lock = threading.Lock()

# /health 에 노출할 간단한 런타임 지표 (부하 측정 시 확인용)
_stats = {
    "started_at": time.time(),
    "analyzed": 0,
    "alerts": 0,
    "purged_keys": 0,
}


def analyze_log(log):
    """
    로그 1건을 받아 Risk Score를 계산한다.

    Redis는 로그를 1건씩 전달하지만,
    Analyzer는 IP/세션별 과거 기록을 state.py의 deque에 누적해
    60초/10분 기준을 계산한다.
    """
    current_time = parse_time(log.get("timestamp"))
    analysis_profile = log.get("analysis_profile", "full")

    total_score = 0
    reasons = []
    rule_hits = []

    detectors = get_detectors_by_profile(analysis_profile)

    # [추가] 상태(deque) 공유 구간은 락으로 직렬화 — Flask 멀티스레드 요청 간 경쟁 방지
    with STATE_LOCK:
        for detector in detectors:
            score, rules, reason = detector(log, current_time)

            total_score += score
            rule_hits.extend(rules)

            if reason:
                reasons.append(reason)

        _stats["analyzed"] += 1
        if STATE_PURGE_EVERY > 0 and _stats["analyzed"] % STATE_PURGE_EVERY == 0:
            _stats["purged_keys"] += purge_idle_keys(current_time, SLOW_WINDOW_SECONDS)

    total_score = min(total_score, 100)
    level = get_level(total_score)
    alert = total_score > ALERT_THRESHOLD

    result = {
        "timestamp": log.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
        "event_id": log.get("event_id"),
        "trace_id": log.get("trace_id"),
        "event_type": log.get("event_type", "unknown"),
        "analysis_profile": analysis_profile,

        "tenant_id": log.get("tenant_id", "unknown"),
        "company_name": log.get("company_name"),

        "ip": log.get("ip", "unknown"),
        "session_id": log.get("session_id", "unknown"),

        "method": log.get("method", "GET"),
        "host": log.get("host", ""),
        "path": log.get("path", ""),
        "status_code": safe_int(log.get("status_code")),

        "action_on_match": log.get("action_on_match", "unknown"),

        "risk_score": total_score,
        "level": level,
        "alert": alert,
        "rule_hits": rule_hits,
        "reasons": reasons,
    }

    return result


def create_alert_event(result):
    """
    Risk Score가 80점을 초과하면 SOAR/LLM 단계로 넘길 Alert Event 생성
    """
    event_data = {
        "event_type": "SECURITY_ALERT",
        "timestamp": result["timestamp"],
        "event_id": result.get("event_id"),
        "trace_id": result.get("trace_id"),

        "tenant_id": result["tenant_id"],
        "company_name": result.get("company_name"),

        "attacker_ip": result["ip"],
        "session_id": result["session_id"],

        "method": result["method"],
        "host": result["host"],
        "path": result["path"],
        "status_code": result["status_code"],

        "action_on_match": result.get("action_on_match"),

        "risk_score": result["risk_score"],
        "level": result["level"],
        "rule_hits": result["rule_hits"],
        "reasons": result["reasons"],

        "action_required": "SEND_TO_LLM_ANALYSIS",
    }

    with _alert_file_lock:
        with open(ALERT_EVENTS_PATH, "a", encoding="utf-8") as file:
            file.write(json.dumps(event_data, ensure_ascii=False) + "\n")

    return event_data


@app.route("/", methods=["GET"])
def health_check():
    return jsonify({
        "status": "running",
        "service": "Aegis Security Detection Engine"
    })


@app.route("/health", methods=["GET"])
def health():
    """
    [추가] demo_setup.sh 가 http://localhost:5001/health 로 점검하는데 라우트가 없어서
    항상 404(⚠)가 떴다. 상태 저장소 크기도 같이 노출해 부하/soak 테스트 중 메모리 추이를 본다.
    """
    with STATE_LOCK:
        tracked_keys = sum(len(store) for store in ALL_STATE_STORES)
    return jsonify({
        "status": "ok",
        "service": "Aegis Security Detection Engine",
        "uptime_seconds": round(time.time() - _stats["started_at"], 1),
        "analyzed": _stats["analyzed"],
        "alerts": _stats["alerts"],
        "tracked_keys": tracked_keys,
        "purged_keys": _stats["purged_keys"],
        "alert_threshold": ALERT_THRESHOLD,
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Worker가 Redis 이벤트 로그를 POST로 보내면 Risk Score 결과를 반환한다.

    통신 구멍:
    Worker → POST /analyze
    """
    log = request.get_json(silent=True)

    # [수정] 잘못된 JSON 이면 Flask 기본 HTML 400 대신 JSON 400 을 돌려준다.
    #        (dict 가 아닌 JSON — 배열/문자열 — 도 거절)
    if not log or not isinstance(log, dict):
        return jsonify({"error": "JSON log is required"}), 400

    result = analyze_log(log)
    alert_event = None

    if result["alert"]:
        _stats["alerts"] += 1
        alert_event = create_alert_event(result)

    return jsonify({
        "detection_result": result,
        "alert_event": alert_event
    })


if __name__ == "__main__":
    print("Aegis Security Detection Engine started")
    app.run(host="0.0.0.0", port=5000)