# =========================
# app.py
# Flask API 서버 / Risk Score 계산 / Alert Event 생성
# =========================

from flask import Flask, request, jsonify
import json
import time

from soar.risk_score_engine.config import ALERT_THRESHOLD
from soar.risk_score_engine.utils import parse_time, get_level
from soar.risk_score_engine.detectors import get_detectors_by_profile

app = Flask(__name__)


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

    for detector in detectors:
        score, rules, reason = detector(log, current_time)

        total_score += score
        rule_hits.extend(rules)

        if reason:
            reasons.append(reason)

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
        "status_code": int(log.get("status_code", 0)),

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

    with open("alert_events.jsonl", "a", encoding="utf-8") as file:
        file.write(json.dumps(event_data, ensure_ascii=False) + "\n")

    return event_data


@app.route("/", methods=["GET"])
def health_check():
    return jsonify({
        "status": "running",
        "service": "Aegis Security Detection Engine"
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Worker가 Redis 이벤트 로그를 POST로 보내면 Risk Score 결과를 반환한다.

    통신 구멍:
    Worker → POST /analyze
    """
    log = request.get_json()

    if not log:
        return jsonify({"error": "JSON log is required"}), 400

    result = analyze_log(log)
    alert_event = None

    if result["alert"]:
        alert_event = create_alert_event(result)

    return jsonify({
        "detection_result": result,
        "alert_event": alert_event
    })


if __name__ == "__main__":
    print("Aegis Security Detection Engine started")
    app.run(host="0.0.0.0", port=5000)