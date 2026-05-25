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