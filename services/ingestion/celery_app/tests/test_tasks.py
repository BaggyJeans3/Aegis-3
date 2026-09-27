"""
SOAR worker 파이프라인 테스트 (Redis → detection-engine → Mongo → 고위험 대응).
외부 의존성은 전부 가짜로 대체한다.
"""
import json

import pytest

import tasks


# ------------------------------------------------------------------
# 가짜 의존성
# ------------------------------------------------------------------

class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, detection_result):
        self.detection_result = detection_result
        self.calls = 0

    def post(self, url, json=None, timeout=None):
        self.calls += 1
        return FakeResponse({"detection_result": self.detection_result, "alert_event": None})


class FakeCollection:
    def __init__(self):
        self.docs = []

    def insert_one(self, doc):
        self.docs.append(doc)

        class R:
            inserted_id = len(self.docs)
        return R()


class FakeRedis:
    def __init__(self, queue=None):
        self.kv = {}
        self.lists = {tasks.REDIS_QUEUE_NAME: list(queue or [])}
        self.rpop_calls = []

    def exists(self, k):
        return 1 if k in self.kv else 0

    def get(self, k):
        return self.kv.get(k)

    def setex(self, k, ttl, v):
        self.kv[k] = v

    def set(self, k, v, nx=False, ex=None):
        if nx and k in self.kv:
            return None
        self.kv[k] = v
        return True

    def incr(self, k):
        self.kv[k] = int(self.kv.get(k, 0)) + 1
        return self.kv[k]

    def rpop(self, name, count=None):
        self.rpop_calls.append(count)
        lst = self.lists.setdefault(name, [])
        if count is None:
            return lst.pop() if lst else None
        out = []
        while lst and len(out) < count:
            out.append(lst.pop())
        return out or None


def _detection(score, level="LOW", hits=None, alert=False):
    return {"risk_score": score, "level": level, "alert": alert, "rule_hits": hits or [],
            "reasons": [], "analysis_profile": "full", "action_on_match": "honeypot"}


@pytest.fixture
def pipeline(monkeypatch):
    """(session, collection, redis, calls) 를 돌려주고 tasks 모듈의 의존성을 가짜로 바꾼다."""
    calls = {"report": 0, "inject": 0, "llm": 0}
    coll = FakeCollection()
    fake_redis = FakeRedis()

    def _setup(detection_result, llm=None):
        session = FakeSession(detection_result)
        monkeypatch.setattr(tasks, "_get_http_session", lambda: session)
        monkeypatch.setattr(tasks, "get_mongo_collection", lambda: coll)
        monkeypatch.setattr(tasks, "redis_client", fake_redis)

        def _report(ip, t):
            calls["report"] += 1

        def _inject(rule):
            calls["inject"] += 1

        def _llm(ev):
            calls["llm"] += 1
            if isinstance(llm, Exception):
                raise llm
            return llm

        monkeypatch.setattr(tasks, "_report_to_analyzer", _report)
        monkeypatch.setattr(tasks, "_inject_rule_to_nginx", _inject)
        monkeypatch.setattr(tasks, "generate_waf_rule_with_feedback", _llm)
        return session, coll, fake_redis, calls

    return _setup


EVENT = {"event_id": "e-1", "ip": "203.0.113.9", "path": "/.env", "method": "GET",
         "event_type": "honeypot_hit", "action_on_match": "honeypot", "headers": {}}


# ------------------------------------------------------------------
# process_security_log
# ------------------------------------------------------------------

def test_low_risk_stored_once_without_response(pipeline):
    session, coll, _, calls = pipeline(_detection(10))
    out = tasks.process_security_log(json.dumps({**EVENT, "event_type": "access_event", "action_on_match": "proxy"}))
    assert out["status"] == "success"
    assert len(coll.docs) == 1
    assert calls == {"report": 0, "inject": 0, "llm": 0}


def test_high_risk_triggers_report_llm_blacklist_and_inject(pipeline):
    rule = {"rule_name": "Env_Probe", "regex": r"/\.env", "confidence_score": 90}
    _, coll, fake_redis, calls = pipeline(_detection(90, "CRITICAL", ["R-ASSET-001"], True), llm=rule)
    tasks.process_security_log(dict(EVENT))
    assert len(coll.docs) == 1
    assert calls == {"report": 1, "inject": 1, "llm": 1}
    assert fake_redis.exists("aegis:blacklist:203.0.113.9")


def test_llm_exception_does_not_retry_or_duplicate(pipeline):
    """[회귀] LLM 예외가 태스크 retry 로 번져 Mongo 중복 저장/보고 반복되던 문제."""
    _, coll, fake_redis, calls = pipeline(_detection(90, "CRITICAL", ["R-ASSET-001"], True),
                                          llm=RuntimeError("GEMINI_API_KEY 없음"))
    out = tasks.process_security_log(dict(EVENT))
    assert out["status"] == "success"
    assert len(coll.docs) == 1
    assert calls["report"] == 1
    assert calls["inject"] == 0
    # LLM 실패여도 블랙리스트 등록은 유지 (기존 설계: 성공/실패 모두 등록)
    assert fake_redis.exists("aegis:blacklist:203.0.113.9")


def test_blacklisted_ip_skips_llm_but_still_reports(pipeline):
    _, coll, fake_redis, calls = pipeline(_detection(90, "CRITICAL", [], True), llm={"rule_name": "x", "regex": "x"})
    fake_redis.setex("aegis:blacklist:203.0.113.9", 60, "1")
    out = tasks.process_security_log(dict(EVENT))
    assert out["reason"] == "ip_blacklisted"
    assert calls == {"report": 1, "inject": 0, "llm": 0}
    assert len(coll.docs) == 1


def test_cluster_cache_hit_skips_llm(pipeline):
    rule = {"rule_name": "Env_Probe", "regex": "x"}
    _, _, fake_redis, calls = pipeline(_detection(90, "CRITICAL", [], True), llm=rule)
    tasks.process_security_log(dict(EVENT))
    # 같은 패턴, 다른 IP → 클러스터 캐시 hit
    out = tasks.process_security_log({**EVENT, "event_id": "e-2", "ip": "203.0.113.77"})
    assert out["reason"] == "cluster_cache_hit"
    assert calls["llm"] == 1


def test_report_cooldown_per_ip(pipeline, monkeypatch):
    """같은 IP 고위험 이벤트가 연달아 와도 analyzer 보고(CF/Slack/Email)는 쿨다운 동안 1회."""
    monkeypatch.setattr(tasks, "REPORT_COOLDOWN_SECONDS", 600)
    _, coll, fake_redis, calls = pipeline(_detection(90, "CRITICAL", [], True), llm=None)
    for i in range(5):
        tasks.process_security_log({**EVENT, "event_id": f"e-{i}", "path": f"/.env{i}"})
    assert calls["report"] == 1
    assert len(coll.docs) == 5          # 저장은 전부
    assert fake_redis.kv["aegis:stats:report_suppressed"] == 4
    tasks.process_security_log({**EVENT, "event_id": "other", "ip": "203.0.113.200"})
    assert calls["report"] == 2          # 다른 IP 는 별도


def test_report_cooldown_disabled(pipeline, monkeypatch):
    monkeypatch.setattr(tasks, "REPORT_COOLDOWN_SECONDS", 0)
    _, _, _, calls = pipeline(_detection(90, "CRITICAL", [], True), llm=None)
    for i in range(3):
        tasks.process_security_log({**EVENT, "event_id": f"e-{i}"})
    assert calls["report"] == 3


def test_report_cooldown_fail_open_on_redis_error(pipeline, monkeypatch):
    monkeypatch.setattr(tasks, "REPORT_COOLDOWN_SECONDS", 600)
    _, _, fake_redis, calls = pipeline(_detection(90, "CRITICAL", [], True), llm=None)

    def boom(*a, **kw):
        raise ConnectionError("redis down")

    monkeypatch.setattr(fake_redis, "set", boom)
    tasks.process_security_log(dict(EVENT))
    assert calls["report"] == 1


def test_threshold_boundary_uses_ge(pipeline, monkeypatch):
    monkeypatch.setattr(tasks, "AI_RULE_THRESHOLD", 80)
    _, _, _, calls = pipeline(_detection(79, "HIGH"), llm=None)
    tasks.process_security_log(dict(EVENT))
    assert calls["llm"] == 0
    _, _, _, calls = pipeline(_detection(80, "HIGH"), llm=None)
    tasks.process_security_log({**EVENT, "ip": "198.51.100.80"})
    assert calls["llm"] == 1


# ------------------------------------------------------------------
# consume_logs_from_redis_queue
# ------------------------------------------------------------------

def test_consume_drains_up_to_batch_with_rpop_count(monkeypatch):
    # LPUSH 순서 재현: 리스트 앞(head)=최신, 뒤(tail)=가장 오래된 q-0
    fake_redis = FakeRedis(queue=[json.dumps({"event_id": f"q-{i}"}) for i in reversed(range(250))])
    monkeypatch.setattr(tasks, "redis_client", fake_redis)
    monkeypatch.setattr(tasks, "CONSUME_BATCH_SIZE", 1000)
    dispatched = []
    monkeypatch.setattr(tasks.process_security_log, "delay", lambda raw: dispatched.append(raw))

    tasks.consume_logs_from_redis_queue()

    assert len(dispatched) == 250
    assert all(c is not None for c in fake_redis.rpop_calls)  # count 인자 사용
    # 오래된 이벤트부터(LPUSH/RPOP = FIFO)
    assert json.loads(dispatched[0])["event_id"] == "q-0"


def test_consume_respects_batch_limit(monkeypatch):
    fake_redis = FakeRedis(queue=[json.dumps({"event_id": f"q-{i}"}) for i in range(500)])
    monkeypatch.setattr(tasks, "redis_client", fake_redis)
    monkeypatch.setattr(tasks, "CONSUME_BATCH_SIZE", 150)
    dispatched = []
    monkeypatch.setattr(tasks.process_security_log, "delay", lambda raw: dispatched.append(raw))
    tasks.consume_logs_from_redis_queue()
    assert len(dispatched) == 150
    assert len(fake_redis.lists[tasks.REDIS_QUEUE_NAME]) == 350


def test_pipeline_tasks_do_not_store_results():
    """결과 백엔드 누적(Redis 메모리) 방지."""
    assert tasks.process_security_log.ignore_result is True
    assert tasks.consume_logs_from_redis_queue.ignore_result is True


# ------------------------------------------------------------------
# build_mongo_document — 포털이 읽는 스키마 정합
# ------------------------------------------------------------------

@pytest.mark.parametrize("event_type,action", [
    ("waf_blocked", "block"), ("blocked_request", "block"), ("honeypot_hit", "honeypot"),
])
def test_confirmed_malicious_escalated_to_critical(event_type, action):
    doc = tasks.build_mongo_document(
        {"event_id": "x", "event_type": event_type, "action_on_match": action},
        {"detection_result": _detection(0)},
    )
    sa = doc["security_analysis"]
    assert (sa["risk_score"], sa["level"], sa["alert"]) == (100, "CRITICAL", True)
    assert sa["reasons"]


def test_mongo_document_has_portal_fields():
    doc = tasks.build_mongo_document({"event_id": "x", "event_type": "access_event"},
                                     {"detection_result": _detection(30, "SUSPICIOUS", ["R-RATE-001"])})
    for k in ("event_id", "trace_id", "raw_event", "security_analysis", "created_at"):
        assert k in doc
    for k in ("risk_score", "level", "alert", "rule_hits", "reasons", "analysis_profile", "action_on_match"):
        assert k in doc["security_analysis"]
    assert doc["created_at"].endswith("Z")


# ------------------------------------------------------------------
# 클러스터링 정규화
# ------------------------------------------------------------------

def test_cluster_key_ignores_ip_order_encoding_and_numbers():
    a = {"method": "GET", "path": "/users", "query": "id=1%27+OR+1=1&b=2", "ip": "1.1.1.1"}
    b = {"method": "get", "path": "/USERS", "query": "b=7&id=9' OR 1=1", "ip": "2.2.2.2"}
    assert tasks.compute_cluster_key(a) == tasks.compute_cluster_key(b)


def test_cluster_key_distinguishes_different_payloads():
    a = {"method": "GET", "path": "/users", "query": "id=1 UNION SELECT"}
    b = {"method": "GET", "path": "/users", "query": "q=<script>"}
    assert tasks.compute_cluster_key(a) != tasks.compute_cluster_key(b)


def test_mongo_client_reused_per_process(monkeypatch):
    created = []

    class DummyClient:
        def __init__(self, uri):
            created.append(uri)

        def __getitem__(self, name):
            return {"c": name}

    monkeypatch.setattr(tasks, "MongoClient", DummyClient)
    monkeypatch.setattr(tasks, "_mongo_client", None)
    monkeypatch.setattr(tasks, "_mongo_client_pid", None)
    for _ in range(5):
        tasks._get_mongo_client()
    assert len(created) == 1
