# =========================
# detectors.py
# 실제 탐지 로직
# =========================

import re

from soar.risk_score_engine.config import (
    FAST_WINDOW_SECONDS,
    SLOW_WINDOW_SECONDS,
    NORMAL_P95_PER_MINUTE,
    SENSITIVE_RULES,
    DOUBLE_ENCODING_PATTERNS,
    PATH_TRAVERSAL_PATTERNS,
    SSRF_PATTERNS,
    COMMAND_INJECTION_PATTERNS,
)

from soar.risk_score_engine.state import (
    ip_404_paths_fast,
    ip_404_paths_slow,
    ip_requests_fast,
    ip_sensitive_categories,
    session_unauthorized_objects,
    session_login_failures,
    session_jwt_errors,
    session_recovery_events,
)

from soar.risk_score_engine.utils import (
    remove_old_time_events,
    remove_old_pair_events,
    is_match_any,
    get_request_text,
    is_sequential_access,
)


def detect_path_enumeration(log, current_time):
    """
    경로 열거 및 스캐닝 행위 탐지

    기준:
    - 고유 404 path 15개 이상 / 60초 → +25
    - 고유 404 path 30개 이상 / 60초 → +40
    - 고유 404 path 50개 이상 / 10분 → +40
    """
    status_code = int(log.get("status_code", 0))

    if status_code != 404:
        return 0, [], None

    ip = log.get("ip", "unknown")
    path = log.get("path", "")

    ip_404_paths_fast[ip].append((current_time, path))
    ip_404_paths_slow[ip].append((current_time, path))

    remove_old_pair_events(ip_404_paths_fast[ip], current_time, FAST_WINDOW_SECONDS)
    remove_old_pair_events(ip_404_paths_slow[ip], current_time, SLOW_WINDOW_SECONDS)

    unique_fast_paths = set(path for _, path in ip_404_paths_fast[ip])
    unique_slow_paths = set(path for _, path in ip_404_paths_slow[ip])

    score = 0
    rule_hits = []
    reasons = []

    if len(unique_fast_paths) >= 30:
        score += 40
        rule_hits.append("R-SCAN-002")
        reasons.append(f"60초 안에 고유 404 path {len(unique_fast_paths)}개 발생")
    elif len(unique_fast_paths) >= 15:
        score += 25
        rule_hits.append("R-SCAN-001")
        reasons.append(f"60초 안에 고유 404 path {len(unique_fast_paths)}개 발생")

    if len(unique_slow_paths) >= 50:
        score += 40
        rule_hits.append("R-SCAN-003")
        reasons.append(f"10분 안에 고유 404 path {len(unique_slow_paths)}개 발생")

    if not reasons:
        return 0, [], None

    return min(score, 100), rule_hits, ", ".join(reasons)


def detect_object_authorization_bypass(log, current_time):
    """
    객체 권한 우회 시도 탐지, BOLA/IDOR

    기준:
    - 권한 없는 객체 ID 3개 이상 / 60초 → +40
    - 권한 없는 객체 ID 10개 이상 / 60초 → +60
    - 연속 ID 접근 패턴 → +20 추가
    """
    session_id = log.get("session_id", "unknown")
    user_id = log.get("user_id")
    target_user_id = log.get("target_user_id")
    object_id = log.get("object_id") or target_user_id

    authorization_result = log.get("authorization_result")

    if authorization_result:
        is_unauthorized = str(authorization_result).lower() in [
            "denied",
            "forbidden",
            "unauthorized",
        ]
    else:
        if not user_id or not target_user_id:
            return 0, [], None

        is_unauthorized = str(user_id) != str(target_user_id)

    if not is_unauthorized:
        return 0, [], None

    session_unauthorized_objects[session_id].append((current_time, str(object_id)))
    remove_old_pair_events(session_unauthorized_objects[session_id], current_time, FAST_WINDOW_SECONDS)

    unique_object_ids = set(object_id for _, object_id in session_unauthorized_objects[session_id])

    score = 0
    rule_hits = []
    reasons = []

    if len(unique_object_ids) >= 10:
        score += 60
        rule_hits.append("R-BOLA-002")
        reasons.append(f"60초 안에 권한 없는 객체 ID {len(unique_object_ids)}개 접근")
    elif len(unique_object_ids) >= 3:
        score += 40
        rule_hits.append("R-BOLA-001")
        reasons.append(f"60초 안에 권한 없는 객체 ID {len(unique_object_ids)}개 접근")

    if is_sequential_access(unique_object_ids):
        score += 20
        rule_hits.append("R-BOLA-003")
        reasons.append("연속 ID 접근 패턴 탐지")

    if not reasons:
        return 0, [], None

    return min(score, 100), rule_hits, ", ".join(reasons)


def detect_sensitive_asset_access(log, current_time):
    """
    노출 자산 접근 시도 탐지

    기준:
    - 민감 경로 1회 접근 → +40
    - 민감 경로 카테고리 3종 이상 / 60초 → +20 추가
    """
    ip = log.get("ip", "unknown")
    path = log.get("path", "")

    matched_category = None

    for category, pattern in SENSITIVE_RULES:
        if re.search(pattern, path, re.IGNORECASE):
            matched_category = category
            break

    if not matched_category:
        return 0, [], None

    ip_sensitive_categories[ip].append((current_time, matched_category))
    remove_old_pair_events(ip_sensitive_categories[ip], current_time, FAST_WINDOW_SECONDS)

    categories = set(category for _, category in ip_sensitive_categories[ip])

    score = 40
    rule_hits = ["R-ASSET-001"]
    reasons = [f"민감 경로 접근 탐지: {path} ({matched_category})"]

    if len(categories) >= 3:
        score += 20
        rule_hits.append("R-ASSET-002")
        reasons.append(f"60초 안에 민감 경로 카테고리 {len(categories)}종 접근")

    return min(score, 100), rule_hits, ", ".join(reasons)


def detect_api_resource_overuse(log, current_time):
    """
    API 자원 사용량 초과 탐지

    기준:
    - max(100회, 정상 p95의 3배) / 60초 → +30
    - max(200회, 정상 p95의 6배) / 60초 → +50
    """
    ip = log.get("ip", "unknown")

    ip_requests_fast[ip].append(current_time)
    remove_old_time_events(ip_requests_fast[ip], current_time, FAST_WINDOW_SECONDS)

    request_count = len(ip_requests_fast[ip])

    first_threshold = max(100, NORMAL_P95_PER_MINUTE * 3)
    second_threshold = max(200, NORMAL_P95_PER_MINUTE * 6)

    score = 0
    rule_hits = []
    reasons = []

    if request_count >= second_threshold:
        score += 50
        rule_hits.append("R-RATE-002")
        reasons.append(f"60초 안에 요청 {request_count}회 발생")
    elif request_count >= first_threshold:
        score += 30
        rule_hits.append("R-RATE-001")
        reasons.append(f"60초 안에 요청 {request_count}회 발생")

    if not reasons:
        return 0, [], None

    return min(score, 100), rule_hits, ", ".join(reasons)


def detect_auth_token_abuse(log, current_time):
    """
    인증/토큰 남용 탐지

    기준:
    - 로그인 실패 10회 이상 / 60초 → +40
    - 토큰 오류 10회 이상 / 60초 → +40
    - OTP/비밀번호 재설정 반복 5회 이상 / 60초 → +60
    """
    session_id = log.get("session_id", "unknown")
    path = log.get("path", "").lower()
    status_code = int(log.get("status_code", 0))

    event_type = str(log.get("event_type", "")).lower()
    auth_error = str(log.get("auth_error", "")).lower()

    score = 0
    rule_hits = []
    reasons = []

    is_login_path = any(keyword in path for keyword in [
        "/login",
        "/signin",
        "/auth/login",
    ])

    is_login_failure = is_login_path and status_code in [401, 403]

    if is_login_failure:
        session_login_failures[session_id].append(current_time)
        remove_old_time_events(session_login_failures[session_id], current_time, FAST_WINDOW_SECONDS)

        count = len(session_login_failures[session_id])

        if count >= 10:
            score += 40
            rule_hits.append("R-AUTH-001")
            reasons.append(f"60초 안에 로그인 실패 {count}회 발생")

    is_jwt_error = (
        "jwt" in auth_error
        or "token" in auth_error
        or event_type in ["invalid_jwt", "malformed_jwt", "token_error"]
    )

    if is_jwt_error:
        session_jwt_errors[session_id].append(current_time)
        remove_old_time_events(session_jwt_errors[session_id], current_time, FAST_WINDOW_SECONDS)

        count = len(session_jwt_errors[session_id])

        if count >= 10:
            score += 40
            rule_hits.append("R-AUTH-002")
            reasons.append(f"60초 안에 JWT/토큰 오류 {count}회 발생")

    is_recovery_path = any(keyword in path for keyword in [
        "/otp",
        "/verify-otp",
        "/password/reset",
        "/reset-password",
        "/forgot-password",
        "/auth/recovery",
    ])

    is_recovery_event = event_type in [
        "otp_verify",
        "otp_failed",
        "password_reset",
        "password_reset_verify",
        "account_recovery",
    ]

    if is_recovery_path or is_recovery_event:
        session_recovery_events[session_id].append(current_time)
        remove_old_time_events(session_recovery_events[session_id], current_time, FAST_WINDOW_SECONDS)

        count = len(session_recovery_events[session_id])

        if count >= 5:
            score += 60
            rule_hits.append("R-AUTH-003")
            reasons.append(f"60초 안에 OTP/비밀번호 재설정 관련 요청 {count}회 발생")

    if not reasons:
        return 0, [], None

    return min(score, 100), rule_hits, ", ".join(reasons)


def detect_payload_bypass(log, current_time):
    """
    Payload 우회 패턴 탐지

    기준:
    - double encoding, path traversal → +50
    - SSRF 의심 요청 → +60
    - command injection 의심 → +60
    """
    request_text = get_request_text(log)

    score = 0
    rule_hits = []
    reasons = []

    if is_match_any(DOUBLE_ENCODING_PATTERNS, request_text) or is_match_any(PATH_TRAVERSAL_PATTERNS, request_text):
        score += 50
        rule_hits.append("R-PAYLOAD-001")
        reasons.append("double encoding 또는 path traversal 패턴 탐지")

    if is_match_any(SSRF_PATTERNS, request_text):
        score += 60
        rule_hits.append("R-PAYLOAD-002")
        reasons.append("SSRF 의심 요청 탐지")

    if is_match_any(COMMAND_INJECTION_PATTERNS, request_text):
        score += 60
        rule_hits.append("R-PAYLOAD-003")
        reasons.append("command injection 의심 문자열 탐지")

    if not reasons:
        return 0, [], None

    return min(score, 100), rule_hits, ", ".join(reasons)


def get_detectors_by_profile(analysis_profile):
    """
    Proxy가 Redis 이벤트에 넣는 analysis_profile 기준으로 탐지 범위를 나눈다.

    rate_only:
    - 정상 proxy 요청용
    - 요청량 폭증 탐지만 수행

    full:
    - honeypot/block/log_only/no_matching_route용
    - 전체 탐지 수행
    """
    if analysis_profile == "rate_only":
        return [
            detect_api_resource_overuse,
        ]

    return [
        detect_path_enumeration,
        detect_object_authorization_bypass,
        detect_sensitive_asset_access,
        detect_api_resource_overuse,
        detect_auth_token_abuse,
        detect_payload_bypass,
    ]