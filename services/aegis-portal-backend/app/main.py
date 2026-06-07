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
from .customers import (
    create_customer,
    list_customers,
    list_owned_tenant_ids,
    list_owned_domains,
    get_admin_tenant_summary,
    list_all_tenants_for_admin,
)
from .auth import get_current_user, get_auth_context, get_auth_context_sse, AuthContext


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 두 DB에 모두 연결: MongoDB(로그) + PostgreSQL(고객사)
    await connect_to_mongo()
    await connect_to_postgres()
    yield
    await close_postgres_connection()
    await close_mongo_connection()


app = FastAPI(title="Aegis Portal Backend", version="0.4.0", lifespan=lifespan)

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
    """
    soar 의 평평한 스키마 -> 프론트가 기대하는 중첩 스키마로 변환.

    soar (실제 MongoDB):
        {
          _id, event_id, trace_id,
          raw_event: { tenant_id, ip, method, path, status_code, timestamp, ... },
          security_analysis: { risk_score, level, action_on_match, rule_hits, ... },
          created_at
        }

    프론트 (기존):
        {
          _id,
          event: { id, timestamp },
          subject: { tenant_id, user: { id } },
          source: { nat_ip },
          http: { request: { method, path }, response: { status_code } },
          security_analysis: { risk_score, action, rule_id, flags: {...} }
        }
    """
    if doc is None:
        return doc

    raw = doc.get("raw_event") or {}
    sec = doc.get("security_analysis") or {}

    # rule_hits 리스트의 첫 번째 항목을 rule_id 로 매핑 (없으면 None)
    rule_hits = sec.get("rule_hits") or []
    rule_id = rule_hits[0] if rule_hits else None

    # soar 의 risk_score 는 0-100 정수. 프론트는 0-1 실수 기대.
    raw_score = sec.get("risk_score", 0)
    try:
        normalized_score = float(raw_score) / 100.0
    except (TypeError, ValueError):
        normalized_score = 0.0

    # tenant_id 가 null/'' 이면(예: Coraza 차단 로그가 host→tenant 매핑 실패 시)
    # host 를 표시용 tenant 힌트로 사용. (실제 필터는 _resolve_tenant_filter 가 host 로 매칭)
    display_tenant_id = raw.get("tenant_id") or raw.get("host") or "unknown"

    return {
        "_id": str(doc.get("_id", "")),
        "event": {
            "id": doc.get("event_id"),
            "timestamp": raw.get("timestamp") or doc.get("created_at"),
        },
        "subject": {
            "tenant_id": display_tenant_id,
            "user": {
                # soar 에 user.id 가 없으므로 session_id 일부를 사용
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
            # soar 스키마엔 개별 플래그 없음. 기본 False.
            "flags": {
                "is_bola": False,
                "is_shadow_api": False,
                "is_data_leak": False,
            },
        },
        # 부수 정보 (프론트에서 안 써도 됨)
        "company_name": raw.get("company_name"),
        "level": sec.get("level"),
        "alert": sec.get("alert", False),
    }


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

    [중요] 필터 필드명은 새 스키마 기준: raw_event.tenant_id
    """
    if ctx.is_admin:
        if requested_tenant_id:
            return {"raw_event.tenant_id": requested_tenant_id}
        return None  # 전체

    # customer: 본인 소유 tenant_id 매칭 + 본인 소유 도메인(host) 매칭 (OR).
    # Coraza 차단 로그가 host→tenant 매핑 실패로 tenant_id=null 이어도,
    # 본인 도메인으로 들어온 트래픽이면 본인 화면에 보이도록 host 로도 매칭한다.
    owned_tenants = await list_owned_tenant_ids(ctx.user_id)
    owned_domains = await list_owned_domains(ctx.user_id)

    if not owned_tenants and not owned_domains:
        # 등록한 고객사 자체가 없으면 어떤 로그도 못 봄
        return {"raw_event.tenant_id": {"$in": []}}  # 0개 매칭

    if requested_tenant_id:
        # 요청한 tenant 가 본인 소유인지 확인
        if requested_tenant_id not in owned_tenants:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="해당 tenant 에 접근 권한이 없습니다.",
            )
        or_conditions = [{"raw_event.tenant_id": requested_tenant_id}]
        if owned_domains:
            # 그 도메인으로 들어온 tenant_id=null 차단 로그도 함께
            or_conditions.append({
                "raw_event.host": {"$in": owned_domains},
                "raw_event.tenant_id": {"$in": [None, ""]},
            })
        return {"$or": or_conditions}

    # tenant 미지정 -> 본인 소유 tenant 전체 + 본인 도메인 차단로그(tenant null)
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

    [주의] 길2 (soar 실제 데이터) 전환 후엔 이 엔드포인트가 의미 없음.
    호출하지 말 것. 실제 soar 데이터가 지워질 수 있음.
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
    action: Optional[str] = Query(None, description="proxy/block/honeypot/log_only"),
    min_risk: float = Query(0.0, ge=0.0, le=1.0),
    is_bola: Optional[bool] = None,  # soar 스키마엔 없음 - 무시
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

    [중요] 쿼리 필드 새 스키마 기준:
      raw_event.tenant_id, raw_event.path
      security_analysis.action_on_match, security_analysis.risk_score

    프론트엔 _to_frontend_schema 로 변환해서 반환.
    """
    coll = get_collection()

    query: dict = {}

    # 권한 기반 tenant 필터
    tenant_filter = await _resolve_tenant_filter(ctx, tenant_id)
    if tenant_filter:
        query.update(tenant_filter)

    # 그 외 일반 필터 (새 스키마 기준)
    if action:
        query["security_analysis.action_on_match"] = action

    # min_risk 는 프론트에서 0-1 로 받지만 soar 는 0-100 으로 저장.
    # 변환해서 쿼리.
    if min_risk > 0.0:
        query["security_analysis.risk_score"] = {"$gte": min_risk * 100}

    # is_bola 는 soar 스키마에 없으므로 무시. (필요 시 reasons 안에 있을 수도)

    if search:
        query["raw_event.path"] = {"$regex": search, "$options": "i"}

    total = await coll.count_documents(query)
    skip = (page - 1) * page_size

    # 정렬: 새 스키마의 created_at 기준 (또는 raw_event.timestamp)
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
    """
    대시보드 통계 (인증 필수).
      - admin: 전체 통계. tenant_id 주면 그 고객사만.
      - customer: 본인 소유 tenant 로 자동 필터링.

    [중요] 새 스키마 기준 집계.
    """
    coll = get_collection()
    match: dict = {}

    tenant_filter = await _resolve_tenant_filter(ctx, tenant_id)
    if tenant_filter:
        match.update(tenant_filter)

    base = [{"$match": match}] if match else []

    # 액션별 카운트 (proxy / block / honeypot / log_only)
    by_action = {
        d["_id"]: d["count"]
        async for d in coll.aggregate(base + [
            {"$group": {"_id": "$security_analysis.action_on_match",
                        "count": {"$sum": 1}}},
        ])
    }

    # 국가별 정보는 soar 스키마에 없음. 빈 배열 반환.
    by_country: list = []

    # 위협 플래그는 soar 스키마에 없음. 대신 level 기반 카운트로 대체.
    flag_counts = {
        "is_bola": 0,
        "is_shadow_api": 0,
        "is_data_leak": 0,
    }

    total = await coll.count_documents(match)
    # high_risk: soar 스키마에선 risk_score 가 0-100. 80 이상.
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
    """
    드롭다운용 tenant 목록 (인증 필수).
      - admin: MongoDB 로그에 등장하는 모든 tenant_id
      - customer: 본인이 소유한 tenant_id 만 (로그 유무 무관)

    [중요] distinct 필드 새 스키마 기준: raw_event.tenant_id
    """
    if ctx.is_admin:
        coll = get_collection()
        tenants = await coll.distinct("raw_event.tenant_id")
        # None 값 제거 후 정렬
        tenants = sorted([t for t in tenants if t])
        return {"tenants": tenants}
    # customer: PostgreSQL에서 본인 소유 가져옴
    owned = await list_owned_tenant_ids(ctx.user_id)
    return {"tenants": sorted(owned)}


@app.get("/api/logs/stream")
async def logs_stream(
    tenant_id: Optional[str] = None,
    ctx: AuthContext = Depends(get_auth_context_sse),
):
    """
    SSE 실시간 로그 스트림 (인증 필수).

    인증: Authorization 헤더 우선, 없으면 쿼리 파라미터 ?token=<JWT> 로 fallback.
    브라우저 기본 EventSource 는 커스텀 헤더를 못 보내므로 보통 ?token= 을 사용한다.
    (get_auth_context_sse 가 둘 다 처리)

    권한:
      - admin: tenant_id 지정 가능. 미지정 시 전체.
      - customer: 본인 소유 외 tenant_id 는 403.

    [중요] stream_source 도 새 스키마로 변환해서 반환해야 프론트가 정상 표시.
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
            resolved_tenant = owned[0]

    async def gen():
        # 연결 직후 한 번 코멘트 전송 → 클라이언트가 '연결됨' 으로 인식
        yield ": connected\n\n"
        async for log in event_stream(resolved_tenant):
            # keepalive 센티넬: 데이터 아님. SSE 코멘트로 연결만 유지.
            if isinstance(log, dict) and log.get("_keepalive"):
                yield ": keepalive\n\n"
                continue
            # stream_source 가 raw 데이터를 줄 경우 변환.
            # 이미 변환된 형태면 _to_frontend_schema 가 안전하게 처리.
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


@app.get("/api/admin/tenants/summary")
async def admin_tenants_summary(
    ctx: AuthContext = Depends(get_auth_context),
):
    """
    관리자 대시보드 카드용 요약.
      - 전체 / 활성 / 비활성 / 정지 고객사 수
      - 가장 최근 가입한 고객사
    admin 만 호출 가능. customer 가 호출하면 403.
    """
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
    """
    관리자가 보는 전체 고객사 목록.
    각 tenant 에 등록된 도메인 정보(routers JOIN)도 같이 반환.
    admin 만 호출 가능. customer 가 호출하면 403.
    """
    if not ctx.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="관리자 전용 엔드포인트입니다.",
        )
    tenants = await list_all_tenants_for_admin()
    return {"tenants": tenants, "total": len(tenants)}