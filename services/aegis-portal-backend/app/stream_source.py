"""
SSE 스트림의 데이터 소스.

==================================================================
이 파일이 길1 -> 길2 전환의 핵심 격리 지점입니다.
------------------------------------------------------------------
  길1 (지금):   event_stream() = dummy_stream()
                더미 로그를 주기적으로 생성 + MongoDB에도 저장.
                실제 SOAR 파이프라인이 없어도 대시보드가 실시간으로 동작.

  길2 (나중):   event_stream() = change_stream()
                팀원 SOAR가 MongoDB에 로그를 넣으면, Change Stream이
                그 신규 문서를 감지해서 그대로 푸시.
                전환 시 맨 아래 한 줄(event_stream = ...)만 바꾸면 됨.
                main.py, 프론트 코드는 그대로.

  주의: change_stream()은 MongoDB가 replica set 모드일 때만 동작.
       (docker-compose의 mongodb 서비스에 --replSet 옵션 추가 필요)
==================================================================
"""
import asyncio
import random
from datetime import datetime, timezone

from .database import get_collection
from .seed_data import generate_log


async def dummy_stream(tenant_id: str = None):
    """
    [길1] 더미 로그를 3~7초 간격으로 하나씩 생성.
    생성한 로그는 MongoDB에도 저장 -> /api/logs 새로고침에도 반영됨.
    """
    coll = get_collection()
    seq = 0
    while True:
        await asyncio.sleep(random.uniform(3, 7))
        seq += 1
        is_attack = random.random() < 0.35
        log = generate_log(is_attack, datetime.now(timezone.utc), seq)

        # tenant 필터가 있으면 해당 테넌트로 강제
        if tenant_id:
            log["subject"]["tenant_id"] = tenant_id

        # MongoDB에 저장 (실시간 + 조회 일관성)
        await coll.insert_one(log)

        # _id를 문자열로 바꿔서 내보냄
        log["_id"] = str(log["_id"])
        ts = log.get("event", {}).get("timestamp")
        if isinstance(ts, datetime):
            log["event"]["timestamp"] = ts.isoformat()
        yield log


async def change_stream(tenant_id: str = None):
    """
    [길2] MongoDB Change Stream으로 신규 로그를 실시간 감지.
    길2 전환 시 맨 아래 event_stream 을 이 함수로 교체.

    팀원 SOAR(tasks.py)가 insert_one 으로 로그를 넣을 때마다
    여기서 즉시 감지되어 푸시됨.
    """
    coll = get_collection()

    pipeline = [{"$match": {"operationType": "insert"}}]
    if tenant_id:
        pipeline[0]["$match"]["fullDocument.subject.tenant_id"] = tenant_id

    async with coll.watch(pipeline, full_document="updateLookup") as stream:
        async for change in stream:
            doc = change["fullDocument"]
            doc["_id"] = str(doc["_id"])
            ts = doc.get("event", {}).get("timestamp")
            if isinstance(ts, datetime):
                doc["event"]["timestamp"] = ts.isoformat()
            yield doc


# ===== 전환 스위치 =====
# 길1: dummy_stream  /  길2: change_stream
event_stream = dummy_stream
