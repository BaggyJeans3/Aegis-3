import json

import pytest

import tasks


class FakeRedis:
    def __init__(self):
        self.kv = {}

    def get(self, k):
        return self.kv.get(k)

    def setex(self, k, _ttl, v):
        self.kv[k] = str(v)

    def exists(self, k):
        return int(k in self.kv)

    def incr(self, k):
        self.kv[k] = str(int(self.kv.get(k, 0)) + 1)
        return int(self.kv[k])


class Resp:
    def __init__(self, status, body=None):
        self.status_code, self._body = status, body or {}
        self.ok = status < 400
        self.text = json.dumps(self._body)

    def json(self):
        return self._body

    def raise_for_status(self):
        pass


@pytest.fixture
def env(monkeypatch):
    """Redis·Mongo·사이드카·Risk 엔진·LLM 을 가짜로 바꾼 워커 파이프라인."""
    r = FakeRedis()
    calls = {"llm": 0, "inject": [], "rearm": [], "events": []}
    state = {"rearm_status": 200}

    def fake_post(url, json=None, timeout=None):
        if url.endswith("/analyze"):
            return Resp(200, {"detection_result": {"risk_score": 90, "level": "CRITICAL"}})
        if url.endswith("/inject"):
            calls["inject"].append(json["rule"])
            return Resp(200, {"status": "shadow_injected"})
        if "/rearm/" in url:
            calls["rearm"].append(url.rsplit("/", 1)[1])
            return Resp(state["rearm_status"], {})
        return Resp(200, {})  # analyzer report

    def fake_llm(_log, meta=None):
        calls["llm"] += 1
        meta.update(model="fake", attempts=1, errors=[])
        return {"rule_name": "SQLi", "regex": "union\\s+select", "confidence_score": 90}

    class Col:
        def insert_one(self, doc):
            calls["events"].append(doc)

            class R:
                inserted_id = 1
            return R()

    monkeypatch.setattr(tasks, "redis_client", r)
    monkeypatch.setattr(tasks.requests, "post", fake_post)
    monkeypatch.setattr(tasks, "generate_waf_rule_with_feedback", fake_llm)
    monkeypatch.setattr(tasks, "get_mongo_collection", lambda name=None: Col())
    return r, calls, state


def event(ip, id_value):
    return {"event_id": f"e-{ip}", "ip": ip, "method": "GET", "path": "/api/items",
            "query": f"id={id_value} union select", "headers": {}}


def run(ev):
    return tasks.process_security_log.run(ev)


def forget_cluster_cache(r):
    for k in [k for k in r.kv if k.startswith("aegis:cluster:")]:
        del r.kv[k]


def test_same_attack_rearms_instead_of_llm(env):
    r, calls, _ = env
    run(event("1.1.1.1", 1))
    assert calls["llm"] == 1 and len(calls["inject"]) == 1
    rule_id = calls["inject"][0].split("id:")[1].split(",")[0]

    forget_cluster_cache(r)  # 5분 캐시가 지난 뒤, 다른 IP·다른 숫자의 같은 공격
    out = run(event("2.2.2.2", 777))
    assert calls["llm"] == 1  # LLM 재호출 없음
    assert calls["rearm"] == [rule_id]
    assert out["reason"] == "rearmed" and str(out["rule_id"]) == rule_id
    assert r.exists("aegis:blacklist:2.2.2.2")  # LLM 경로와 동일하게 IP 차단
    types = [e.get("type") for e in calls["events"]]
    assert types.count("generated") == 1 and types.count("auto_rearm") == 1


def test_already_active_rule_skips_llm(env):
    r, calls, state = env
    run(event("1.1.1.1", 1))
    forget_cluster_cache(r)
    state["rearm_status"] = 409
    assert run(event("2.2.2.2", 2))["reason"] == "already_active"
    assert calls["llm"] == 1


def test_missing_archive_falls_back_to_llm(env):
    r, calls, state = env
    run(event("1.1.1.1", 1))
    forget_cluster_cache(r)
    state["rearm_status"] = 404  # 보관본 없음 → 기존대로 LLM
    run(event("2.2.2.2", 2))
    assert calls["llm"] == 2


def test_different_attack_goes_to_llm(env):
    r, calls, _ = env
    run(event("1.1.1.1", 1))
    forget_cluster_cache(r)
    other = dict(event("2.2.2.2", 1), path="/admin/.env")
    run(other)
    assert calls["llm"] == 2 and calls["rearm"] == []


def test_honeypot_hit_triggers_ai_rule_even_with_zero_score(env, monkeypatch):
    r, calls, _ = env
    real_post = tasks.requests.post

    def zero_score(url, json=None, timeout=None):
        if url.endswith("/analyze"):
            return Resp(200, {"detection_result": {"risk_score": 0, "level": "LOW"}})
        return real_post(url, json=json, timeout=timeout)

    monkeypatch.setattr(tasks.requests, "post", zero_score)
    run(dict(event("3.3.3.3", 1), event_type="honeypot_hit", path="/.env"))
    assert calls["llm"] == 1

    run(dict(event("4.4.4.4", 1), event_type="request", path="/other"))  # 0점 일반 요청은 그대로 제외
    run(dict(event("5.5.5.5", 1), event_type="waf_blocked", path="/x"))  # CRS 차단 이벤트도 제외
    assert calls["llm"] == 1
