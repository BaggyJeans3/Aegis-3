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
  GET  /api/admin/tenants/summary  관리자 카드용 요약
  GET  /api/admin/tenants          관리자 전체 고객사 목록

권한 정책:
  - 모든 /api/* (health/seed 제외)는 JWT 인증 필수
  - admin (app_metadata.user_role == "ADMIN") -> 전체 데이터
  - customer (그 외)                          -> 본인 소유 tenant_id 로만 필터

데이터 저장소:
  MongoDB    - 트래픽 로그 (database.py, traffic_logs 컬렉션)
  PostgreSQL - 고객사/라우팅 정보 (postgres.py)

================================================================
[중요] 스키마 변경
----------------------------------------------------------------
soar 시스템이 traffic_logs 에 INSERT 하는 실제 스키마는 평평한 구조:
  raw_event.{tenant_id, ip, method, path, status_code, timestamp, ...}
  security_analysis.{risk_score, level, action_on_match, rule_hits, ...}

본인 프론트는 옛 더미용 중첩 스키마를 기대:
  subject.tenant_id, source.nat_ip, http.request.method, ...

해결: 백엔드가 응답 시점에 평평한 스키마 -> 중첩 스키마로 변환.
프론트 코드 변경 없음.
================================================================
"""
"""
Aegis 포털 백엔드 (FastAPI).

[변경 사항]
  - _resolve_tenant_filter:
    customer 권한일 때 tenant_id 매칭 + host 매칭 (OR) 으로 변경.
    Coraza 차단 로그가 tenant_id=null 로 들어와도 host 로 본인 도메인 매칭.

  - 새 import: list_owned_domains
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
from .seed_data import generate_logs
from .stream_source import event_stream
from .postgres import connect_to_postgres, close_postgres_connection
from .customers import (
    create_customer,
    list_customers,
    list_owned_tenant_ids,
    list_owned_domains,   # ← 새 함수
    get_admin_tenant_summary,
    list_all_tenants_for_admin,
)
from .auth import get_current_user, get_auth_context, AuthContext


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_to_mongo()
    await connect_to_postgres()
    yield
    await close_postgres_connection()
    await close_mongo_connection()


app = FastAPI(title="Aegis Portal Backend", version="0.5.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://dashboard.aegis3.cloud",
        "https://aegis-3.baggyjeans2026.workers.dev",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _to_frontend_schema(doc: dict) -> dict:
    """soar 평평한 스키마 -> 프론트 중첩 스키마 변환."""
    if doc is None:
        return doc

    raw = doc.get("raw_event") or {}
    sec = doc.get("security_analysis") or {}

    rule_hits = sec.get("rule_hits") or []
    rule_id = rule_hits[0] if rule_hits else None

    raw_score = sec.get("risk_score", 0)
    try:
        normalized_score = float(raw_score) / 100.0
    except (TypeError, ValueError):
        normalized_score = 0.0

    # tenant_id 가 null 일 때 host 기반으로 추론 표시 (응답용)
    tenant_id = raw.get("tenant_id")
    if not tenant_id:
        # null/'' 인 경우 host 를 표시 힌트로
        tenant_id = raw.get("host") or "unknown"

    return {
        "_id": str(doc.get("_id", "")),
        "event": {
            "id": doc.get("event_id"),
            "timestamp": raw.get("timestamp") or doc.get("created_at"),
        },
        "subject": {
            "tenant_id": tenant_id,
            "user": {
                "id": (raw.get("session_id") or "unknown")[:32],
            },
        },
        "source": {
            "nat_ip": raw.get("ip"),
        },
        "http": {
            "request": {
                "method": raw.get("method") or "GET",
                "path": raw.get("path") or "/",
            },
            "response": {
                "status_code": int(raw.get("status_code") or 0),
            },
        },
        "security_analysis": {
            "risk_score": normalized_score,
            "action": sec.get("action_on_match") or "unknown",
            "rule_id": rule_id,
            "flags": {
                "is_bola": False,
                "is_shadow_api": False,
                "is_data_leak": False,
            },
        },
        "company_name": raw.get("company_name"),
        "level": sec.get("level"),
        "alert": sec.get("alert", False),
    }


async def _resolve_tenant_filter(
    ctx: AuthContext, requested_tenant_id: Optional[str]
) -> Optional[dict]:
    """
    권한에 따라 MongoDB 쿼리에 추가할 필터를 결정.

    [중요 변경]
    customer 권한:
      - 본인이 소유한 tenant_id 매칭 (정상 트래픽)
      - OR 본인이 소유한 inbound_domain 매칭 (Coraza 차단 등 tenant_id null 인 경우)

    이렇게 OR 로 묶어서 - 본인 도메인으로 들어온 트래픽은
    tenant_id 가 박혀있든 null 이든 다 본인 화면에 표시됨.
    """
    if ctx.is_admin:
        if requested_tenant_id:
            return {"raw_event.tenant_id": requested_tenant_id}
        return None  # admin 전체

    # customer: 본인 소유 tenant_id + host 매칭
    owned_tenants = await list_owned_tenant_ids(ctx.user_id)
    owned_domains = await list_owned_domains(ctx.user_id)

    if not owned_tenants and not owned_domains:
        # 등록한 고객사 자체가 없음
        return {"raw_event.tenant_id": {"$in": []}}

    if requested_tenant_id:
        # 특정 tenant 요청 - 본인 소유인지 확인
        if requested_tenant_id not in owned_tenants:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="해당 tenant 에 접근 권한이 없습니다.",
            )
        # 그 tenant_id 매칭 + 그 tenant 의 도메인 매칭 (둘 다)
        # 본인 소유 도메인 중 그 tenant 의 거만 가져옴
        # (단순화: 전체 owned_domains 사용. customer 가 여러 tenant 가지면 약간 넓게 매칭)
        or_conditions = [
            {"raw_event.tenant_id": requested_tenant_id},
        ]
        if owned_domains:
            or_conditions.append({
                "raw_event.host": {"$in": owned_domains},
                "raw_event.tenant_id": {"$in": [None, ""]},
            })
        return {"$or": or_conditions}

    # tenant 미지정 - 본인 소유 전체
    or_conditions = []
    if owned_tenants:
        or_conditions.append({"raw_event.tenant_id": {"$in": owned_tenants}})
    if owned_domains:
        or_conditions.append({
            "raw_event.host": {"$in": owned_domains},
            "raw_event.tenant_id": {"$in": [None, ""]},
        })

    if not or_conditions:
        return {"raw_event.tenant_id": {"$in": []}}
    if len(or_conditions) == 1:
        return or_conditions[0]
    return {"$or": or_conditions}


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "aegis-portal-backend"}


# ===== [길1 전용] 더미 시드 =====
@app.post("/api/seed")
async def seed(
    count: int = Query(200, ge=1, le=2000),
    ctx: AuthContext = Depends(get_auth_context),
):
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


@app.get("/api/logs")
async def get_logs(
    tenant_id: Optional[str] = None,
    action: Optional[str] = Query(None, description="proxy/block/honeypot/log_only"),
    min_risk: float = Query(0.0, ge=0.0, le=1.0),
    is_bola: Optional[bool] = None,
    search: Optional[str] = Query(None, description="path 부분 일치 검색"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    ctx: AuthContext = Depends(get_auth_context),
):
    """로그 목록 조회 (인증 필수)."""
    coll = get_collection()

    query: dict = {}

    tenant_filter = await _resolve_tenant_filter(ctx, tenant_id)
    if tenant_filter:
        query.update(tenant_filter)

    if action:
        query["security_analysis.action_on_match"] = action

    if min_risk > 0.0:
        query["security_analysis.risk_score"] = {"$gte": min_risk * 100}

    if search:
        query["raw_event.path"] = {"$regex": search, "$options": "i"}

    total = await coll.count_documents(query)
    skip = (page - 1) * page_size

    cursor = (
        coll.find(query)
        .sort("created_at", -1)
        .skip(skip)
        .limit(page_size)
    )
    docs = [_to_frontend_schema(d) async for d in cursor]

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
    """대시보드 통계 (인증 필수)."""
    coll = get_collection()
    match: dict = {}

    tenant_filter = await _resolve_tenant_filter(ctx, tenant_id)
    if tenant_filter:
        match.update(tenant_filter)

    base = [{"$match": match}] if match else []

    by_action = {
        d["_id"]: d["count"]
        async for d in coll.aggregate(base + [
            {"$group": {"_id": "$security_analysis.action_on_match",
                        "count": {"$sum": 1}}},
        ])
    }

    by_country: list = []

    flag_counts = {
        "is_bola": 0,
        "is_shadow_api": 0,
        "is_data_leak": 0,
    }

    total = await coll.count_documents(match)
    high_risk = await coll.count_documents(
        {**match, "security_analysis.risk_score": {"$gte": 80}}
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
    """드롭다운용 tenant 목록."""
    if ctx.is_admin:
        coll = get_collection()
        tenants = await coll.distinct("raw_event.tenant_id")
        tenants = sorted([t for t in tenants if t])
        return {"tenants": tenants}
    owned = await list_owned_tenant_ids(ctx.user_id)
    return {"tenants": sorted(owned)}


@app.get("/api/logs/stream")
async def logs_stream(
    tenant_id: Optional[str] = None,
    ctx: AuthContext = Depends(get_auth_context),
):
    """SSE 실시간 로그 스트림."""
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
            resolved_tenant = owned[0]

    async def gen():
        async for log in event_stream(resolved_tenant):
            converted = _to_frontend_schema(log) if "raw_event" in log else log
            yield f"data: {json.dumps(converted, default=str)}\n\n"
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
    supabase_user_id = user.get("sub")
    if not supabase_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="토큰에 sub 클레임 없음",
        )
    customers = await list_customers(supabase_user_id)
    return {"customers": customers}


@app.get("/api/admin/tenants/summary")
async def admin_tenants_summary(
    ctx: AuthContext = Depends(get_auth_context),
):
    if not ctx.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="관리자 전용 엔드포인트입니다.",
        )
    return await get_admin_tenant_summary()


@app.get("/api/admin/tenants")
async def admin_all_tenants(
    ctx: AuthContext = Depends(get_auth_context),
):
    if not ctx.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="관리자 전용 엔드포인트입니다.",
        )
    tenants = await list_all_tenants_for_admin()
    return {"tenants": tenants, "total": len(tenants)}