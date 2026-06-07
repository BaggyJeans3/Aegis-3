"""
고객사(테넌트) 등록/조회 로직.

흐름:
  등록 -> tenants 테이블에 INSERT (회사명, 요금제, 명세서, supabase_user_id)
       -> 거기서 나온 tenant_id 로 routers 테이블에도 INSERT (도메인, 오리진)
  조회 -> supabase_user_id 로 그 회원이 소유한 고객사 목록 반환

api_key 는 백엔드가 자동 생성한다.
"""
import json
import secrets
import uuid

from .postgres import get_pool


def _generate_api_key() -> str:
    """대시보드 접근용 API Key 생성. 'aegis_' + 32자 랜덤 hex."""
    return "aegis_" + secrets.token_hex(16)


async def create_customer(
    company_name: str,
    plan_type: str,
    spec_text: str,
    supabase_user_id: str,
    inbound_domain: str,
    target_origin: str,
) -> dict:
    """
    고객사 1건 등록. tenants + routers 에 같은 트랜잭션으로 INSERT.
    둘 중 하나라도 실패하면 전체 롤백.
    """
    pool = get_pool()
    api_key = _generate_api_key()

    # supabase_user_id 가 유효한 UUID 인지 확인 (아니면 None 으로)
    try:
        su_id = uuid.UUID(supabase_user_id)
    except (ValueError, AttributeError, TypeError):
        su_id = None

    async with pool.acquire() as conn:
        async with conn.transaction():
            # 1. tenants 삽입
            tenant_row = await conn.fetchrow(
                """
                INSERT INTO tenants
                    (company_name, api_key, plan_type, supabase_user_id, spec_text)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING tenant_id, company_name, api_key, plan_type,
                          status, created_at
                """,
                company_name, api_key, plan_type, su_id, spec_text,
            )

            # 2. routers 삽입 (보호 도메인 라우팅 규칙)
            #    target_origin 이 비어있으면 NULL 로 (허니팟/차단 대비)
            await conn.execute(
                """
                INSERT INTO routers
                    (tenant_id, inbound_domain, target_origin, action_on_match)
                VALUES ($1, $2, $3, $4)
                """,
                tenant_row["tenant_id"],
                inbound_domain,
                target_origin if target_origin else None,
                "proxy",
            )

    return {
        "tenant_id": str(tenant_row["tenant_id"]),
        "company_name": tenant_row["company_name"],
        "api_key": tenant_row["api_key"],
        "plan_type": tenant_row["plan_type"],
        "status": tenant_row["status"],
        "created_at": tenant_row["created_at"].isoformat(),
    }


async def list_customers(supabase_user_id: str) -> list:
    """
    특정 Supabase 회원이 소유한 고객사 목록 조회.
    supabase_user_id 가 없으면 빈 목록.
    """
    try:
        su_id = uuid.UUID(supabase_user_id)
    except (ValueError, AttributeError, TypeError):
        return []

    pool = get_pool()
    rows = await pool.fetch(
        """
        SELECT tenant_id, company_name, api_key, plan_type, status,
               spec_text, created_at
        FROM tenants
        WHERE supabase_user_id = $1
        ORDER BY created_at DESC
        """,
        su_id,
    )
    return [
        {
            "tenant_id": str(r["tenant_id"]),
            "company_name": r["company_name"],
            "api_key": r["api_key"],
            "plan_type": r["plan_type"],
            "status": r["status"],
            "spec_text": r["spec_text"],
            "created_at": r["created_at"].isoformat(),
        }
        for r in rows
    ]


async def list_owned_tenant_ids(supabase_user_id: str) -> list[str]:
    """
    특정 회원이 소유한 tenant_id 문자열 목록만 반환.
    멀티 테넌트 로그 필터링에 사용 (일반 사용자가 자기 로그만 보게).
    """
    try:
        su_id = uuid.UUID(supabase_user_id)
    except (ValueError, AttributeError, TypeError):
        return []

    pool = get_pool()
    rows = await pool.fetch(
        "SELECT tenant_id FROM tenants WHERE supabase_user_id = $1",
        su_id,
    )
    return [str(r["tenant_id"]) for r in rows]


async def list_owned_domains(supabase_user_id: str) -> list[str]:
    """
    특정 회원이 소유한 모든 inbound_domain 목록 반환.

    Coraza 차단 트래픽은 sidecar 가 host→tenant 매핑에 실패하면 tenant_id=null 로
    저장되고 raw_event.host 에 도메인만 남는다. 이 경우에도 본인 고객사 차단 로그를
    보여주려면 tenant_id 매칭 외에 host 매칭도 필요하므로, 본인 소유 도메인을 반환한다.
    """
    try:
        su_id = uuid.UUID(supabase_user_id)
    except (ValueError, AttributeError, TypeError):
        return []

    pool = get_pool()
    rows = await pool.fetch(
        """
        SELECT DISTINCT r.inbound_domain
        FROM routers r
        JOIN tenants t ON r.tenant_id = t.tenant_id
        WHERE t.supabase_user_id = $1
          AND r.is_active = TRUE
          AND r.inbound_domain IS NOT NULL
        """,
        su_id,
    )
    return [r["inbound_domain"] for r in rows if r["inbound_domain"]]


# ============================================================
# [추가] Admin 전용 함수 - AdminDashboardPage 의 카드/목록용
# ============================================================

async def get_admin_tenant_summary() -> dict:
    """
    관리자 대시보드 카드용 집계 정보.
      - 등록된 고객사 수 (전체)
      - 활성 상태 고객사 수
      - 최근 가입한 고객사 (회사명 + 가입일)
    한 번의 쿼리로 다 처리.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        # 카운트 집계 (전체 + 상태별)
        counts = await conn.fetchrow(
            """
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'active') AS active_count,
                COUNT(*) FILTER (WHERE status = 'inactive') AS inactive_count,
                COUNT(*) FILTER (WHERE status = 'suspended') AS suspended_count
            FROM tenants
            """
        )

        # 가장 최근 가입 1건
        latest = await conn.fetchrow(
            """
            SELECT company_name, created_at
            FROM tenants
            ORDER BY created_at DESC
            LIMIT 1
            """
        )

    return {
        "total": counts["total"],
        "active_count": counts["active_count"],
        "inactive_count": counts["inactive_count"],
        "suspended_count": counts["suspended_count"],
        "latest_company": latest["company_name"] if latest else None,
        "latest_created_at": latest["created_at"].isoformat() if latest else None,
    }


async def list_all_tenants_for_admin() -> list[dict]:
    """
    관리자가 보는 전체 고객사 목록.
    routers 와 LEFT JOIN 해서 등록한 도메인 정보도 같이 반환.

    asyncpg 는 json_agg 결과를 문자열로 반환할 수 있어서,
    routes 를 명시적으로 json.loads 로 파싱해서 항상 배열로 반환.
    """
    pool = get_pool()
    rows = await pool.fetch(
        """
        SELECT
            t.tenant_id,
            t.company_name,
            t.plan_type,
            t.status,
            t.created_at,
            t.supabase_user_id,
            COALESCE(
                json_agg(
                    json_build_object(
                        'inbound_domain', r.inbound_domain,
                        'target_origin', r.target_origin,
                        'action', r.action_on_match
                    )
                ) FILTER (WHERE r.route_id IS NOT NULL),
                '[]'::json
            ) AS routes
        FROM tenants t
        LEFT JOIN routers r
            ON t.tenant_id = r.tenant_id AND r.is_active = TRUE
        GROUP BY
            t.tenant_id, t.company_name, t.plan_type,
            t.status, t.created_at, t.supabase_user_id
        ORDER BY t.created_at DESC
        """
    )

    def _parse_routes(value):
        """asyncpg 가 문자열로 줄 수도, 이미 list 로 줄 수도 있어서 양쪽 다 처리."""
        if isinstance(value, str):
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return []
        if isinstance(value, list):
            return value
        return []

    return [
        {
            "tenant_id": str(r["tenant_id"]),
            "company_name": r["company_name"],
            "plan_type": r["plan_type"],
            "status": r["status"],
            "created_at": r["created_at"].isoformat(),
            "supabase_user_id": str(r["supabase_user_id"]) if r["supabase_user_id"] else None,
            "routes": _parse_routes(r["routes"]),
        }
        for r in rows
    ]