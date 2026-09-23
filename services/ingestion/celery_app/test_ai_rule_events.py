import json

import tasks


class FakeRedis:
    """LPUSH/RPOP/RPUSH 만 흉내내는 리스트 (index 0 = head)."""

    def __init__(self):
        self.q = []

    def lpush(self, _k, *vals):
        for v in vals:
            self.q.insert(0, v)

    def rpush(self, _k, *vals):
        self.q.extend(vals)

    def rpop(self, _k):
        return self.q.pop() if self.q else None


class FakeCollection:
    def __init__(self, fail=False):
        self.docs, self.fail = [], fail

    def insert_many(self, docs):
        if self.fail:
            raise RuntimeError("mongo down")
        self.docs.extend(docs)


def _setup(monkeypatch, fail):
    r, col = FakeRedis(), FakeCollection(fail)
    monkeypatch.setattr(tasks, "redis_client", r)
    monkeypatch.setattr(tasks, "get_mongo_collection", lambda name=None: col)
    for i in range(3):
        r.lpush("q", json.dumps({"type": "shadow_match", "n": i}))
    return r, col


def test_drain_moves_events_in_order(monkeypatch):
    r, col = _setup(monkeypatch, fail=False)
    r.lpush("q", "{broken")  # 깨진 건 버리고 나머지는 적재
    assert tasks.drain_ai_rule_events() == 3
    assert [d["n"] for d in col.docs] == [0, 1, 2]
    assert r.q == []


def test_drain_restores_queue_on_mongo_failure(monkeypatch):
    r, col = _setup(monkeypatch, fail=True)
    assert tasks.drain_ai_rule_events() == 0
    col.fail = False
    assert tasks.drain_ai_rule_events() == 3  # 유실 없이 같은 순서로 재적재
    assert [d["n"] for d in col.docs] == [0, 1, 2]
