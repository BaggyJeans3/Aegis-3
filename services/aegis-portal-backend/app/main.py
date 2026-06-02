"""
Aegis 포털 백엔드 (FastAPI).

엔드포인트:
  GET  /api/health          헬스 체크 (인증 불필요)
  POST /api/seed            더미 로그 삽입 [길1 전용 - 길2 전환 시 삭제]
  POST /api/customers       고객사 등록 (admin/customer 둘 다)
  GET  /api/customers       본인 고객사 목록 조회
  GET  /api/logs            로그 목록 (admin=전체 / customer=본인 tenant)
  GET  /api/stats           통계 (admin=전체 / customer=본인 tenant)
  GET  /api/tenants         테넌트 드롭다운 목록 (admin/customer 분기)
  GET  /api/logs/stream     SSE 실시간 (admin/customer 분기)

권한 정책:
  - 모든 /api/* (health/seed 제외)는 JWT 인증 필수
  - admin (app_metadata.user_role == "ADMIN") -> 전체 데이터
  - customer (그 외)                          -> 본인 소유 tenant_id 로만 필터

데이터 저장소:
  MongoDB    - 트래픽 로그 (database.py)
  PostgreSQL - 고객사/라우팅 정보 (postgres.py)

================================================================
길1 -> 길2 전환 가이드 (나중에 EC2 SOAR 파이프라인이 완성되면)
----------------------------------------------------------------
  1. seed_data.py 파일 삭제
  2. 아래 @app.post("/api/seed") 블록 삭제
  3. stream_source.py 의 dummy_stream() -> change_stream() 으로 교체
================================================================
"""
import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Query, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from .database import connect_to_mongo, close_mongo_connection, get_collection
from .seed_data import generate_logs               # [길1 전용]
from .stream_source import event_stream
from .postgres import connect_to_postgres, close_postgres_connection
from .customers import create_customer, list_customers, list_owned_tenant_ids
from .auth import get_current_user, get_auth_context, AuthContext


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 두 DB에 모두 연결: MongoDB(로그) + PostgreSQL(고객사)
    await connect_to_mongo()
    await connect_to_postgres()
    yield
    await close_postgres_connection()
    await close_mongo_connection()


app = FastAPI(title="Aegis Portal Backend", version="0.3.0", lifespan=lifespan)

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


async def _resolve_tenant_filter(
    ctx: AuthContext, requested_tenant_id: Optional[str]
) -> Optional[dict]:
    """
    권한에 따라 MongoDB 쿼리에 추가할 tenant 필터를 결정.

    반환값:
      None      -> 필터 없음 (admin이 전체 조회할 때)
      {...}     -> MongoDB 쿼리 조각. caller가 query에 병합해 쓰면 됨.

    규칙:
      - admin + tenant_id 지정 -> 그 tenant 만
      - admin + 미지정         -> 전체 (필터 없음)
      - customer               -> 본인 소유 tenant_id 들 (요청값은 본인 소유에 한해서만 적용)
    """
    if ctx.is_admin:
        if requested_tenant_id:
            return {"subject.tenant_id": requested_tenant_id}
        return None  # 전체

    # customer: 본인 소유 tenant 만
    owned = await list_owned_tenant_ids(ctx.user_id)
    if not owned:
        # 등록한 고객사가 없으면 어떤 로그도 못 봄
        return {"subject.tenant_id": {"$in": []}}  # 0개 매칭

    if requested_tenant_id:
        # 요청한 tenant 가 본인 소유인지 확인
        if requested_tenant_id not in owned:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="해당 tenant 에 접근 권한이 없습니다.",
            )
        return {"subject.tenant_id": requested_tenant_id}

    # tenant 지정 안 했으면 본인 소유 전체
    return {"subject.tenant_id": {"$in": owned}}


@app.get("/api/health")
async def health():
    """헬스 체크. 인증 불필요."""
    return {"status": "ok", "service": "aegis-portal-backend"}


# ===== [길1 전용] 더미 시드 - 길2 전환 시 이 블록 삭제 =====
@app.post("/api/seed")
async def seed(
    count: int = Query(200, ge=1, le=2000),
    ctx: AuthContext = Depends(get_auth_context),
):
    """
    더미 로그를 MongoDB에 채움. 기존 데이터는 비우고 새로 삽입.
    admin 만 허용 (테스트 데이터 조작 권한).
    """
    if not ctx.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="admin 권한이 필요합니다.",
        )
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
    ctx: AuthContext = Depends(get_auth_context),
):
    """
    로그 목록 조회 (인증 필수).
      - admin: 모든 로그. tenant_id 주면 그 고객사 한정.
      - customer: 본인 소유 tenant_id 로 자동 필터링.
        본인 소유 아닌 tenant_id 를 명시하면 403.
    """
    coll = get_collection()

    query: dict = {}

    # 권한 기반 tenant 필터
    tenant_filter = await _resolve_tenant_filter(ctx, tenant_id)
    if tenant_filter:
        query.update(tenant_filter)

    # 그 외 일반 필터
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
async def get_stats(
    tenant_id: Optional[str] = None,
    ctx: AuthContext = Depends(get_auth_context),
):
    """
    대시보드 통계 (인증 필수).
      - admin: 전체 통계. tenant_id 주면 그 고객사만.
      - customer: 본인 소유 tenant 로 자동 필터링.
    """
    coll = get_collection()
    match: dict = {}

    tenant_filter = await _resolve_tenant_filter(ctx, tenant_id)
    if tenant_filter:
        match.update(tenant_filter)

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
async def get_tenants(ctx: AuthContext = Depends(get_auth_context)):
    """
    드롭다운용 tenant 목록 (인증 필수).
      - admin: MongoDB 로그에 등장하는 모든 tenant_id
      - customer: 본인이 소유한 tenant_id 만 (로그 유무 무관)
    """
    if ctx.is_admin:
        coll = get_collection()
        tenants = await coll.distinct("subject.tenant_id")
        return {"tenants": sorted(tenants)}
    # customer: PostgreSQL에서 본인 소유 가져옴
    owned = await list_owned_tenant_ids(ctx.user_id)
    return {"tenants": sorted(owned)}


@app.get("/api/logs/stream")
async def logs_stream(
    tenant_id: Optional[str] = None,
    ctx: AuthContext = Depends(get_auth_context),
):
    """
    SSE 실시간 로그 스트림 (인증 필수).

    주의: 브라우저의 EventSource 는 커스텀 헤더(Authorization)를 못 보냄.
    프론트에서는 토큰을 쿼리 파라미터로 보내거나(보안 약함),
    fetch-기반 SSE 라이브러리를 사용해야 함. 지금은 일단 동작 우선.

    권한:
      - admin: tenant_id 지정 가능. 미지정 시 전체.
      - customer: 본인 소유 외 tenant_id 는 403.
    """
    # 권한 사전 검증 (stream 시작 후엔 에러 응답이 어려움)
    resolved_tenant: Optional[str] = None
    if ctx.is_admin:
        resolved_tenant = tenant_id
    else:
        owned = await list_owned_tenant_ids(ctx.user_id)
        if not owned:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="등록된 고객사가 없어 스트림 접근 불가.",
            )
        if tenant_id:
            if tenant_id not in owned:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="해당 tenant 에 접근 권한이 없습니다.",
                )
            resolved_tenant = tenant_id
        else:
            # tenant 지정 안 했으면 첫 번째 소유 tenant 로 스트림
            # (여러 tenant 동시 스트리밍은 현재 stream_source 인터페이스 한 개 인자만 지원)
            resolved_tenant = owned[0]

    async def gen():
        async for log in event_stream(resolved_tenant):
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
    """
    고객사 등록 요청 본문.
    supabase_user_id 는 JWT 토큰에서 추출하므로 본문에 받지 않음.
    """
    company_name: str
    plan_type: str = "FREE"
    spec_text: str
    inbound_domain: str
    target_origin: str = ""


@app.post("/api/customers")
async def post_customer(
    payload: CustomerCreate,
    user: dict = Depends(get_current_user),
):
    """
    고객사 등록. PostgreSQL tenants + routers 에 INSERT.
    api_key 는 백엔드가 자동 생성.
    admin/customer 둘 다 자기 명의로 등록 가능.
    """
    supabase_user_id = user.get("sub")
    if not supabase_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="토큰에 sub 클레임 없음",
        )

    customer = await create_customer(
        company_name=payload.company_name,
        plan_type=payload.plan_type,
        spec_text=payload.spec_text,
        supabase_user_id=supabase_user_id,
        inbound_domain=payload.inbound_domain,
        target_origin=payload.target_origin,
    )
    return customer


@app.get("/api/customers")
async def get_customers(user: dict = Depends(get_current_user)):
    """
    현재 로그인한 회원이 소유한 고객사 목록.
    인증 토큰의 sub 클레임으로 본인 데이터만 반환.
    """
    supabase_user_id = user.get("sub")
    if not supabase_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="토큰에 sub 클레임 없음",
        )
    customers = await list_customers(supabase_user_id)
    return {"customers": customers}