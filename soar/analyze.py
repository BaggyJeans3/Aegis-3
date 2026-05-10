from flask import Flask, request, jsonify
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
import re
import time

app = Flask(__name__)

# =========================
# 1. 기본 설정값
# =========================

WINDOW_SECONDS = 60
ALERT_THRESHOLD = 80

# IP/세션별 최근 요청 기록 저장소
ip_requests = defaultdict(deque)
ip_404_errors = defaultdict(deque)
ip_sensitive_paths = defaultdict(deque)
session_bola_events = defaultdict(deque)

# 공격자가 자주 접근하는 민감 경로 목록
SENSITIVE_PATTERNS = [
    r"^/\.env",
    r"^/admin",
    r"^/wp-admin",
    r"^/config",
    r"^/config\.json",
    r"^/backup",
    r"^/backup\.zip",
    r"^/\.git",
    r"^/phpmyadmin",
    r"^/swagger",
    r"^/actuator",
    r"^/server-status",
]


# =========================
# 2. 공통 유틸 함수
# =========================

def parse_time(timestamp):
    """문자열 시간을 datetime 객체로 변환"""
    if not timestamp:
        return datetime.now()

    timestamp = timestamp.replace("Z", "+00:00")
    return datetime.fromisoformat(timestamp).replace(tzinfo=None)


def remove_old_events(event_queue, current_time):
    """최근 60초보다 오래된 기록 제거"""
    limit_time = current_time - timedelta(seconds=WINDOW_SECONDS)

    while event_queue and event_queue[0] < limit_time:
        event_queue.popleft()


def get_level(score):
    """Risk Score를 위험도 단계로 변환"""
    if score <= 39:
        return "LOW"
    elif score <= 59:
        return "SUSPICIOUS"
    elif score <= 80:
        return "HIGH"
    else:
        return "CRITICAL"


# =========================
# 3. 탐지 로직
# =========================

def detect_rate_limit(log, current_time):
    """
    IP별 요청 빈도 탐지
    60초 안에 같은 IP 요청 100회 이상 → +30점
    60초 안에 같은 IP 요청 200회 이상 → +50점
    """
    ip = log.get("ip", "unknown")

    ip_requests[ip].append(current_time)
    remove_old_events(ip_requests[ip], current_time)

    count = len(ip_requests[ip])

    if count >= 200:
        return 50, ["R-RATE-002"], f"60초 안에 요청 {count}회 발생"
    elif count >= 100:
        return 30, ["R-RATE-001"], f"60초 안에 요청 {count}회 발생"

    return 0, [], None


def detect_404_burst(log, current_time):
    """
    IP별 404 반복 탐지
    60초 안에 같은 IP 404 에러 10회 이상 → +25점
    60초 안에 같은 IP 404 에러 20회 이상 → +40점
    """
    ip = log.get("ip", "unknown")
    status_code = int(log.get("status_code", 0))

    if status_code != 404:
        return 0, [], None

    ip_404_errors[ip].append(current_time)
    remove_old_events(ip_404_errors[ip], current_time)

    count = len(ip_404_errors[ip])

    if count >= 20:
        return 40, ["R-404-002"], f"60초 안에 404 에러 {count}회 발생"
    elif count >= 10:
        return 25, ["R-404-001"], f"60초 안에 404 에러 {count}회 발생"

    return 0, [], None


def detect_sensitive_path(log, current_time):
    """
    민감 경로 접근 탐지
    민감 경로 접근 1회 → +30점
    60초 안에 같은 IP가 민감 경로 3회 이상 접근 → 추가 +20점
    """
    ip = log.get("ip", "unknown")
    path = log.get("path", "")

    is_sensitive = any(
        re.search(pattern, path, re.IGNORECASE)
        for pattern in SENSITIVE_PATTERNS
    )

    if not is_sensitive:
        return 0, [], None

    score = 30
    rule_hits = ["R-PATH-001"]
    reason = f"민감 경로 접근 탐지: {path}"

    ip_sensitive_paths[ip].append(current_time)
    remove_old_events(ip_sensitive_paths[ip], current_time)

    count = len(ip_sensitive_paths[ip])

    if count >= 3:
        score += 20
        rule_hits.append("R-PATH-002")
        reason += f", 60초 안에 민감 경로 {count}회 접근"

    return score, rule_hits, reason


def detect_bola(log, current_time):
    """
    세션별 BOLA 의심 탐지
    같은 세션에서 다른 사용자 리소스 접근 5회 이상 → +35점
    같은 세션에서 다른 사용자 리소스 접근 10회 이상 → +50점
    """
    session_id = log.get("session_id", "unknown")
    user_id = log.get("user_id")
    target_user_id = log.get("target_user_id")

    # user_id 또는 target_user_id가 없으면 정확한 BOLA 판단 불가
    if not user_id or not target_user_id:
        return 0, [], None

    # 자기 리소스 접근이면 정상
    if str(user_id) == str(target_user_id):
        return 0, [], None

    session_bola_events[session_id].append(current_time)
    remove_old_events(session_bola_events[session_id], current_time)

    count = len(session_bola_events[session_id])

    if count >= 10:
        return 50, ["R-BOLA-002"], f"다른 사용자 리소스 접근 {count}회 발생"
    elif count >= 5:
        return 35, ["R-BOLA-001"], f"다른 사용자 리소스 접근 {count}회 발생"

    return 0, [], None


# =========================
# 4. Risk Score 계산
# =========================

def analyze_log(log):
    """
    로그 1건을 받아 4가지 탐지 로직을 실행하고 Risk Score를 계산
    """
    current_time = parse_time(log.get("timestamp"))

    total_score = 0
    reasons = []
    rule_hits = []

    detectors = [
        detect_rate_limit,
        detect_404_burst,
        detect_sensitive_path,
        detect_bola,
    ]

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
        "tenant_id": log.get("tenant_id", "unknown"),
        "ip": log.get("ip", "unknown"),
        "session_id": log.get("session_id", "unknown"),
        "method": log.get("method", "GET"),
        "path": log.get("path", ""),
        "status_code": int(log.get("status_code", 0)),
        "risk_score": total_score,
        "level": level,
        "alert": alert,
        "rule_hits": rule_hits,
        "reasons": reasons,
    }

    return result


# =========================
# 5. Alert Event 생성
# =========================

def create_alert_event(result):
    """
    Risk Score가 80점을 초과하면 SOAR 단계로 넘길 Alert Event 생성
    """
    event_data = {
        "event_type": "SECURITY_ALERT",
        "timestamp": result["timestamp"],
        "tenant_id": result["tenant_id"],
        "attacker_ip": result["ip"],
        "session_id": result["session_id"],
        "method": result["method"],
        "path": result["path"],
        "status_code": result["status_code"],
        "risk_score": result["risk_score"],
        "level": result["level"],
        "rule_hits": result["rule_hits"],
        "reasons": result["reasons"],
        "action_required": "REVIEW_OR_BLOCK",
    }

    with open("alert_events.jsonl", "a", encoding="utf-8") as file:
        file.write(json.dumps(event_data, ensure_ascii=False) + "\n")

    return event_data


# =========================
# 6. API 엔드포인트
# =========================

@app.route("/", methods=["GET"])
def health_check():
    return jsonify({
        "status": "running",
        "service": "Aegis Security Detection Engine"
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    프록시 서버가 로그를 POST로 보내면 탐지 결과를 반환
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


# =========================
# 7. 서버 실행
# =========================

if __name__ == "__main__":
    print("Aegis Security Detection Engine started")
    app.run(host="0.0.0.0", port=5000)
