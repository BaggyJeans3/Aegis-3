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


async def db_poll_stream(tenant_id: str = None):
    """
    [길2 - 폴링] 실제 traffic_logs 를 주기적으로 폴링해 신규 문서를 푸시.

    SOAR(tasks.py)가 insert 한 raw_event 스키마 문서를 '가공 없이' 그대로 yield.
    main.py 의 gen() 이 _to_frontend_schema 로 변환한다(변환 로직 단일화).

    change_stream 과 달리 MongoDB replica set 이 필요 없어 standalone 에서도 동작.
    커서는 _id(ObjectId, 시간순 증가) 기준 $gt 로 신규분만 가져온다.
    신규가 없을 땐 약 14초마다 keepalive 센티넬을 보내 SSE 연결 유지.

    [주의] _id 는 ObjectId 그대로 yield (다음 폴링의 커서로 써야 함).
           문자열화는 _to_frontend_schema 가 사본에서 처리하므로 원본은 보존된다.
    """
    coll = get_collection()

    # 연결 시점의 최신 _id 부터 시작 (과거 로그 폭주 방지)
    last_id = None
    newest = await coll.find_one(sort=[("_id", -1)])
    if newest:
        last_id = newest["_id"]

    idle_ticks = 0
    while True:
        await asyncio.sleep(2)

        query: dict = {}
        if last_id is not None:
            query["_id"] = {"$gt": last_id}
        if tenant_id:
            query["raw_event.tenant_id"] = tenant_id

        found = False
        cursor = coll.find(query).sort("_id", 1).limit(100)
        async for doc in cursor:
            found = True
            last_id = doc["_id"]
            yield doc

        if found:
            idle_ticks = 0
        else:
            idle_ticks += 1
            if idle_ticks >= 7:        # 약 14초 무이벤트 → keepalive
                idle_ticks = 0
                yield {"_keepalive": True}


async def change_stream(tenant_id: str = None):
    """
    [길2 - Change Stream] MongoDB Change Stream 으로 신규 로그를 실시간 감지.

    db_poll_stream 보다 지연이 적지만 MongoDB 가 replica set 모드일 때만 동작
    (docker-compose mongodb 서비스에 --replSet 추가 + rs.initiate() 필요).
    replica set 을 구성했다면 맨 아래 event_stream 을 이 함수로 교체.

    새 스키마(raw_event.tenant_id) 기준으로 필터하고, 문서는 가공 없이 yield
    (변환은 main.py gen() 의 _to_frontend_schema 가 담당).
    """
    coll = get_collection()

    pipeline = [{"$match": {"operationType": "insert"}}]
    if tenant_id:
        pipeline[0]["$match"]["fullDocument.raw_event.tenant_id"] = tenant_id

    async with coll.watch(pipeline, full_document="updateLookup") as stream:
        async for change in stream:
            yield change["fullDocument"]


# ===== 전환 스위치 =====
# 길1: dummy_stream (더미)  /  길2: db_poll_stream (실데이터 폴링, replica set 불필요)
#                          /  길2': change_stream (실데이터 실시간, replica set 필요)
event_stream = db_poll_stream
