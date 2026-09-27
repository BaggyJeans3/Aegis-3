"""
Risk Score Engine 테스트 공통 설정.

- 저장소 루트를 sys.path 에 넣어 `soar.risk_score_engine.*` 로 import (Dockerfile 과 동일한 방식)
- 테스트마다 IP/세션 상태(deque) 초기화 — detector 는 전역 상태를 누적하므로 필수
- ev(): 기준 시각 + offset 초로 이벤트를 만드는 헬퍼 (시간창 테스트를 결정적으로 만들기 위함)
"""
import os
import sys
from datetime import datetime, timedelta

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from soar.risk_score_engine.state import reset_all_state  # noqa: E402

BASE_TIME = datetime(2026, 9, 27, 10, 0, 0)


def make_event(offset_seconds=0, **fields):
    event = {
        "timestamp": (BASE_TIME + timedelta(seconds=offset_seconds)).isoformat() + "Z",
        "analysis_profile": "full",
        "ip": "203.0.113.10",
        "session_id": "sess-1",
        "method": "GET",
        "path": "/",
        "status_code": 200,
        "headers": {"user-agent": "pytest"},
    }
    event.update(fields)
    return event


@pytest.fixture(autouse=True)
def _reset_state():
    reset_all_state()
    yield
    reset_all_state()


@pytest.fixture
def ev():
    return make_event
