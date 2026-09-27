# =========================
# state.py
# IP/세션별 최근 요청 기록 저장소
# =========================

from collections import defaultdict, deque


# Redis는 이벤트를 1건씩 넘긴다.
# Analyzer는 이 deque들에 IP/세션별 최근 이벤트를 누적해서
# 60초/10분 기준 탐지를 수행한다.

# 경로 열거 및 스캐닝 탐지용
ip_404_paths_fast = defaultdict(deque)
ip_404_paths_slow = defaultdict(deque)

# API 요청량 탐지용
ip_requests_fast = defaultdict(deque)

# 민감 경로 접근 탐지용
ip_sensitive_categories = defaultdict(deque)

# BOLA/IDOR 탐지용
session_unauthorized_objects = defaultdict(deque)

# 인증/토큰 남용 탐지용
session_login_failures = defaultdict(deque)
session_jwt_errors = defaultdict(deque)
session_recovery_events = defaultdict(deque)

# =========================
# [추가] 동시성 / 메모리 관리
# =========================

import threading
from datetime import timedelta

# Flask 는 요청을 스레드로 병렬 처리한다. detector 들은 deque 를 순회(set(...))하면서
# 다른 스레드가 같은 deque 에 append 하면 "deque mutated during iteration" 이 날 수 있고,
# 점수 계산도 뒤섞인다. analyze_log 전체를 이 락으로 직렬화한다.
# (연산이 수 μs~수십 μs 라 락 경합 비용은 HTTP 오버헤드 대비 무시 가능)
STATE_LOCK = threading.RLock()

ALL_STATE_STORES = [
    ip_404_paths_fast,
    ip_404_paths_slow,
    ip_requests_fast,
    ip_sensitive_categories,
    session_unauthorized_objects,
    session_login_failures,
    session_jwt_errors,
    session_recovery_events,
]


def _last_time(event_queue):
    """deque 마지막 원소의 시간. (time) 또는 (time, value) 형태 모두 지원."""
    last = event_queue[-1]
    return last[0] if isinstance(last, tuple) else last


def purge_idle_keys(current_time, max_age_seconds):
    """
    마지막 이벤트가 max_age_seconds 보다 오래됐거나 비어 있는 IP/세션 키를 삭제한다.
    defaultdict 는 한 번 본 IP/세션 키를 영원히 들고 있어서, 트래픽이 계속 들어오면
    메모리가 끝없이 늘어난다(soak 테스트에서 드러나는 누수). 이를 주기적으로 정리한다.
    반환값: 삭제한 키 개수
    """
    limit_time = current_time - timedelta(seconds=max_age_seconds)
    removed = 0

    for store in ALL_STATE_STORES:
        for key in list(store.keys()):
            event_queue = store[key]
            if not event_queue or _last_time(event_queue) < limit_time:
                del store[key]
                removed += 1

    return removed


def reset_all_state():
    """테스트/벤치마크용: 모든 상태 저장소 초기화."""
    with STATE_LOCK:
        for store in ALL_STATE_STORES:
            store.clear()
