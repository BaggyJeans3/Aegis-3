"""
Aegis 포털 백엔드 (FastAPI).

엔드포인트:
  GET  /api/health          헬스 체크
  POST /api/seed            더미 로그 삽입   [길1 전용 - 길2 전환 시 삭제]
  GET  /api/logs            로그 목록 조회 (필터 + 페이지네이션)
  GET  /api/stats           대시보드용 집계 통계
  GET  /api/tenants         로그에 존재하는 테넌트 목록
  GET  /api/logs/stream     SSE 실시간 로그 스트림
  POST /api/customers       고객사 등록 (PostgreSQL tenants + routers)
  GET  /api/customers       특정 회원의 고객사 목록 조회

데이터 저장소:
  MongoDB    - 트래픽 로그 (database.py)
  PostgreSQL - 고객사/라우팅 정보 (postgres.py)

================================================================
길1 -> 길2 전환 가이드 (나중에 EC2 SOAR 파이프라인이 완성되면)
----------------------------------------------------------------
  1. seed_data.py 파일 삭제
  2. 아래 @app.post("/api/seed") 블록 삭제
  3. stream_source.py 의 dummy_stream() -> change_stream() 으로 교체
     (MongoDB Change Stream 사용. replica set 모드 필요)
  그 외 /api/logs, /api/stats, 프론트 코드는 그대로 둠.
================================================================
"""
import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from .database import connect_to_mongo, close_mongo_connection, get_collection
from .seed_data import generate_logs       
from .stream_source import event_stream
from .postgres import connect_to_postgres, close_postgres_connection
from .customers import create_customer, list_customers


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 두 DB에 모두 연결: MongoDB(로그) + PostgreSQL(고객사)
    await connect_to_mongo()
    await connect_to_postgres()
    yield
    await close_mongo_connection()
    await close_postgres_connection()


app = FastAPI(title="Aegis Portal Backend", version="0.2.0", lifespan=lifespan)

# Vite 프론트(개발 서버)에서 호출 가능하도록 CORS 허용.
# 운영 시에는 allow_origins를 실제 프론트 도메인으로 좁힐 것.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _serialize(doc: dict) -> dict:
    """MongoDB 문서를 JSON 직렬화 가능하게 변환."""
    if doc is None:
        return doc
    doc["_id"] = str(doc["_id"])
    ts = doc.get("event", {}).get("timestamp")
    if isinstance(ts, datetime):
        doc["event"]["timestamp"] = ts.isoformat()
    return doc


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "aegis-portal-backend"}


# ===== [길1 전용] 더미 시드 - 길2 전환 시 이 블록 삭제 =====
@app.post("/api/seed")
async def seed(count: int = Query(200, ge=1, le=2000)):
    """더미 로그를 MongoDB에 채움. 기존 데이터는 비우고 새로 삽입."""
    coll = get_collection()
    await coll.delete_many({})
    logs = generate_logs(count)
    result = await coll.insert_many(logs)
    return {"inserted": len(result.inserted_ids)}
# ===== [길1 전용] 끝 =====


@app.get("/api/logs")
async def get_logs(
    tenant_id: Optional[str] = None,
    action: Optional[str] = Query(None, description="allowed/blocked/monitored"),
    min_risk: float = Query(0.0, ge=0.0, le=1.0),
    is_bola: Optional[bool] = None,
    search: Optional[str] = Query(None, description="path 부분 일치 검색"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    """
    로그 목록 조회. 모든 필터는 선택 사항.
    멀티 테넌트: tenant_id를 주면 해당 고객사 로그만 반환.
    """
    coll = get_collection()

    query: dict = {}
    if tenant_id:
        query["subject.tenant_id"] = tenant_id
    if action:
        query["security_analysis.action"] = action
    if min_risk > 0.0:
        query["security_analysis.risk_score"] = {"$gte": min_risk}
    if is_bola is not None:
        query["security_analysis.flags.is_bola"] = is_bola
    if search:
        query["http.request.path"] = {"$regex": search, "$options": "i"}

    total = await coll.count_documents(query)
    skip = (page - 1) * page_size

    cursor = (
        coll.find(query)
        .sort("event.timestamp", -1)
        .skip(skip)
        .limit(page_size)
    )
    docs = [_serialize(d) async for d in cursor]

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size,
        "items": docs,
    }


@app.get("/api/stats")
async def get_stats(tenant_id: Optional[str] = None):
    """대시보드 카드/차트용 집계."""
    coll = get_collection()
    match: dict = {}
    if tenant_id:
        match["subject.tenant_id"] = tenant_id

    base = [{"$match": match}] if match else []

    by_action = {
        d["_id"]: d["count"]
        async for d in coll.aggregate(base + [
            {"$group": {"_id": "$security_analysis.action",
                        "count": {"$sum": 1}}},
        ])
    }

    by_country = [
        {"country": d["_id"], "count": d["count"]}
        async for d in coll.aggregate(base + [
            {"$group": {"_id": "$source.geo.country_iso",
                        "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10},
        ])
    ]

    flag_counts = {}
    for flag in ["is_bola", "is_shadow_api", "is_data_leak"]:
        flag_counts[flag] = await coll.count_documents(
            {**match, f"security_analysis.flags.{flag}": True}
        )

    total = await coll.count_documents(match)
    high_risk = await coll.count_documents(
        {**match, "security_analysis.risk_score": {"$gte": 0.8}}
    )

    return {
        "total_logs": total,
        "high_risk_count": high_risk,
        "by_action": by_action,
        "by_country": by_country,
        "threat_flags": flag_counts,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/tenants")
async def get_tenants():
    """로그에 등장하는 테넌트 목록 (프론트 필터 드롭다운용)."""
    coll = get_collection()
    tenants = await coll.distinct("subject.tenant_id")
    return {"tenants": sorted(tenants)}


@app.get("/api/logs/stream")
async def logs_stream(tenant_id: Optional[str] = None):
    """
    SSE 실시간 로그 스트림.
    프론트는 EventSource로 이 엔드포인트를 구독.

    데이터 소스는 stream_source.py 가 담당:
      - 길1(지금): 더미 로그를 주기적으로 생성해서 푸시
      - 길2(나중): MongoDB Change Stream 으로 교체
    이 엔드포인트 자체는 길2 전환 시에도 바뀌지 않음.
    """
    async def gen():
        async for log in event_stream(tenant_id):
            yield f"data: {json.dumps(log, default=str)}\n\n"
            await asyncio.sleep(0)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ===== 고객사(테넌트) 관리 - PostgreSQL =====

class CustomerCreate(BaseModel):
    """고객사 등록 요청 본문. 프론트 ApiManagePage 에서 전송."""
    company_name: str
    plan_type: str = "FREE"
    spec_text: str
    supabase_user_id: str
    inbound_domain: str
    target_origin: str = ""


@app.post("/api/customers")
async def post_customer(payload: CustomerCreate):
    """
    고객사 등록. PostgreSQL tenants + routers 에 INSERT.
    api_key 는 백엔드가 자동 생성.

    참고: 현재 supabase_user_id 는 프론트가 보낸 값을 그대로 신뢰함.
          JWT 검증은 추후 추가 예정.
    """
    customer = await create_customer(
        company_name=payload.company_name,
        plan_type=payload.plan_type,
        spec_text=payload.spec_text,
        supabase_user_id=payload.supabase_user_id,
        inbound_domain=payload.inbound_domain,
        target_origin=payload.target_origin,
    )
    return customer


@app.get("/api/customers")
async def get_customers(supabase_user_id: str = Query(...)):
    """특정 Supabase 회원이 소유한 고객사 목록 조회."""
    customers = await list_customers(supabase_user_id)
    return {"customers": customers}
