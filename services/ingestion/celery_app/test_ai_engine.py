import re

import pytest

from ai_engine import check_re2_compatible

# Python re 는 통과하지만 Go RE2(Coraza) 는 거부하는 패턴
REJECT = [
    r"(?=.*select)union",
    r"(?!admin)\w+",
    r"(?<=id=)\d+",
    r"(?<!\\)'",
    r"(a)\1",
    r"(?>abc)",
    r"a++",
    r"\d*+",
    r"(a)?(?(1)b|c)",
    r"(?x) union \s+ select",
    r"(?a)\w+",
    r"end\Z",
    r"a{1001}",
]

# RE2 에서 유효한 패턴 (이스케이프된 괄호·백슬래시가 오탐되지 않아야 함)
ACCEPT = [
    r"(?i)union\s+select",
    r"(?i:or)\s+1=1",
    r"(?P<k>\w+)=",
    r"\(?=",
    r"\\1",
    r"\.\./",
    r"(?s)<script.*?>",
    r"a{2,1000}",
    r"(%27|')\s*or",
]


@pytest.mark.parametrize("p", REJECT)
def test_reject(p):
    re.compile(p)  # Python 은 통과함을 전제
    with pytest.raises(re.error):
        check_re2_compatible(p)


@pytest.mark.parametrize("p", ACCEPT)
def test_accept(p):
    check_re2_compatible(p)


# --- 재시도 루프: API 오류는 같은 요청 재전송, 답변 오류는 피드백 ---
import json as _json
import types as _types

import ai_engine


class _FakeChat:
    def __init__(self, replies):
        self.replies, self.sent = list(replies), []

    def send_message(self, prompt):
        self.sent.append(prompt)
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return _types.SimpleNamespace(text=r)


def _run_with(monkeypatch, replies):
    chat = _FakeChat(replies)
    client = _types.SimpleNamespace(chats=_types.SimpleNamespace(create=lambda **_: chat))
    monkeypatch.setattr(ai_engine, "_get_client", lambda: client)
    monkeypatch.setattr(ai_engine, "API_RETRY_BASE_SECONDS", 0)
    meta = {}
    return ai_engine.generate_waf_rule_with_feedback({"ip": "1.1.1.1"}, meta=meta), chat, meta


GOOD = _json.dumps({"rule_name": "SQLi", "regex": r"union\s+select"})


def test_api_error_resends_original_prompt(monkeypatch):
    rule, chat, meta = _run_with(monkeypatch, [RuntimeError("503 UNAVAILABLE"), GOOD])
    assert rule["regex"] == r"union\s+select"
    assert chat.sent[0] == chat.sent[1]  # 오류 메시지가 아닌 원래 요청을 재전송
    assert [e["kind"] for e in meta["errors"]] == ["api"]


def test_missing_regex_gets_schema_feedback(monkeypatch):
    rule, chat, meta = _run_with(monkeypatch, [_json.dumps({"rule_name": "x"}), GOOD])
    assert rule is not None
    assert "regex" in chat.sent[1] and chat.sent[1] != chat.sent[0]
    assert [e["kind"] for e in meta["errors"]] == ["schema"]


def test_re2_violation_gets_feedback(monkeypatch):
    bad = _json.dumps({"rule_name": "x", "regex": r"(?=a)b"})
    rule, _, meta = _run_with(monkeypatch, [bad, GOOD])
    assert rule is not None and [e["kind"] for e in meta["errors"]] == ["re2"]
