"""
[로컬 전용] 큐 벤치 하네스용 Celery 워커 진입점.

MongoDB 를 띄울 수 없는 환경(로컬 PC, CI)에서 파이프라인 처리량을 재기 위해
tasks.py 는 그대로 쓰고 '저장 단계'만 Redis 리스트(bench:mongo_docs)로 바꿔 끼운다.
Gemini 는 호출되지 않도록 스텁 처리한다(벤치 이벤트는 AI 임계값 미만이지만 안전장치).

실행 (저장소 루트에서):
  redis-server &                                   # 6379
  python -m soar.risk_score_engine.app &           # detection-engine :5000
  cd services/ingestion/celery_app
  RISK_ANALYZER_URL=http://localhost:5000/analyze \
  PYTHONPATH=.:../../../scripts/soar_bench/local \
  celery -A bench_worker:celery_app worker --beat --loglevel=warning
  # 다른 터미널
  python scripts/soar_bench/queue_bench.py --local-sink redis://localhost:6379/2 --count 3000

MONGO_SINK_DELAY_MS 로 저장 1건당 인위적 지연(실 Mongo insert 흉내)을 줄 수 있다. 기본 2ms.
주의: 실제 MongoDB 연결 비용(특히 매 태스크 MongoClient 생성)은 여기서 재현되지 않는다.
"""
import json
import os
import sys
import time
import types

# --- google.genai 스텁 (ai_engine import 만 통과시키기 위함) -------------------
if "google.genai" not in sys.modules:
    try:
        import google.genai  # noqa: F401
    except Exception:
        google_mod = sys.modules.setdefault("google", types.ModuleType("google"))
        genai = types.ModuleType("google.genai")
        genai.Client = lambda **kw: (_ for _ in ()).throw(RuntimeError("bench: Gemini 비활성"))
        genai_types = types.ModuleType("google.genai.types")
        genai_types.GenerateContentConfig = lambda **kw: None
        genai.types = genai_types
        google_mod.genai = genai
        sys.modules["google.genai"] = genai
        sys.modules["google.genai.types"] = genai_types

import redis  # noqa: E402

import tasks  # noqa: E402  (services/ingestion/celery_app/tasks.py)
from celery_app import celery_app  # noqa: E402,F401

_SINK_URL = os.getenv("BENCH_SINK_URL", "redis://localhost:6379/2")
_DELAY = float(os.getenv("MONGO_SINK_DELAY_MS", "2")) / 1000.0
_sink = None


class _InsertResult:
    def __init__(self, inserted_id):
        self.inserted_id = inserted_id


class _RedisListCollection:
    def insert_one(self, doc):
        global _sink
        if _sink is None:
            _sink = redis.from_url(_SINK_URL, decode_responses=True)
        if _DELAY:
            time.sleep(_DELAY)
        _sink.rpush("bench:mongo_docs", json.dumps(doc, default=str, ensure_ascii=False))
        return _InsertResult(doc.get("event_id"))

    # 개선 버전의 upsert 경로도 지원
    def update_one(self, flt, update, upsert=False):
        doc = dict(update.get("$setOnInsert", {}))
        return self.insert_one(doc)


def _fake_collection():
    return _RedisListCollection()


tasks.get_mongo_collection = _fake_collection
