# =========================
# utils.py
# 공통 유틸 함수
# =========================

from datetime import datetime, timedelta
import json
import re


def parse_time(timestamp):
    """
    문자열 timestamp를 datetime 객체로 변환한다.
    timestamp가 없거나 형식이 이상하면 현재 시간을 사용한다.
    """
    if not timestamp:
        return datetime.now()

    try:
        timestamp = str(timestamp).replace("Z", "+00:00")
        return datetime.fromisoformat(timestamp).replace(tzinfo=None)
    except Exception:
        return datetime.now()


def safe_int(value, default=0):
    """
    status_code 등을 안전하게 정수로 변환한다.
    [수정] 이벤트에 "status_code": null 이나 "abc" 가 오면 int() 가 예외를 던져
    /analyze 가 500 → worker 가 재시도 3회 후 이벤트를 버리는 문제가 있었다.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def remove_old_time_events(event_queue, current_time, window_seconds):
    """
    시간만 저장된 deque에서 window_seconds보다 오래된 기록 제거
    """
    limit_time = current_time - timedelta(seconds=window_seconds)

    while event_queue and event_queue[0] < limit_time:
        event_queue.popleft()


def remove_old_pair_events(event_queue, current_time, window_seconds):
    """
    (시간, 값) 형태 deque에서 window_seconds보다 오래된 기록 제거
    """
    limit_time = current_time - timedelta(seconds=window_seconds)

    while event_queue and event_queue[0][0] < limit_time:
        event_queue.popleft()


def get_level(score):
    """
    Risk Score를 등급으로 변환한다.

    문서 기준:
    0~24 LOW
    25~49 SUSPICIOUS
    50~80 HIGH
    81~100 CRITICAL
    """
    if score <= 24:
        return "LOW"
    elif score <= 49:
        return "SUSPICIOUS"
    elif score <= 80:
        return "HIGH"
    else:
        return "CRITICAL"


def is_match_any(patterns, text):
    """
    여러 정규식 중 하나라도 매칭되는지 확인
    """
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


# 인프라(프록시 체인)가 채우는 IP 헤더. 공격 payload 가 아니므로 payload 탐지 대상에서 제외한다.
# [수정] nginx 2-pass 구조(:80 → 127.0.0.1:8081 → proxy)에서 X-Forwarded-For 는 항상
#   "<client>, 127.0.0.1" 이 되고, 로컬/도커 환경에선 172.x·10.x 가 들어간다.
#   이 값이 SSRF_PATTERNS(127.0.0.1, 사설대역)에 매칭돼 full 분석 이벤트 전부에
#   R-PAYLOAD-002(+60) 오탐이 붙던 문제를 막는다.
INFRA_IP_HEADERS = {
    "x-forwarded-for",
    "x-real-ip",
    "cf-connecting-ip",
    "true-client-ip",
    "forwarded",
}


def get_request_text(log):
    """
    Payload 탐지를 위해 path, query, body, headers를 하나의 문자열로 합친다.
    Proxy Redis 이벤트에 query/body/headers가 들어오도록 맞춰둔다.
    단, 프록시 체인이 붙이는 IP 헤더(INFRA_IP_HEADERS)는 제외한다.
    """
    path = str(log.get("path", ""))
    query = str(log.get("query", ""))
    body = str(log.get("body", ""))
    raw_headers = log.get("headers") or {}
    if isinstance(raw_headers, dict):
        raw_headers = {
            k: v for k, v in raw_headers.items()
            if str(k).lower() not in INFRA_IP_HEADERS
        }
    headers = json.dumps(raw_headers, ensure_ascii=False)

    return f"{path} {query} {body} {headers}"


def extract_number(value):
    """
    user_101, /users/101 같은 값에서 숫자만 추출
    """
    if value is None:
        return None

    match = re.search(r"\d+", str(value))

    if not match:
        return None

    return int(match.group())


def is_sequential_access(object_ids):
    """
    /users/101, /users/102, /users/103 같은 연속 ID 접근인지 확인
    """
    numbers = []

    for object_id in object_ids:
        number = extract_number(object_id)

        if number is not None:
            numbers.append(number)

    numbers = sorted(set(numbers))

    if len(numbers) < 3:
        return False

    for i in range(len(numbers) - 2):
        if numbers[i + 1] == numbers[i] + 1 and numbers[i + 2] == numbers[i] + 2:
            return True

    return False