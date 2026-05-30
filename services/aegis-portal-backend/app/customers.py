"""
고객사(테넌트) 등록/조회 로직.

흐름:
  등록 -> tenants 테이블에 INSERT (회사명, 요금제, 명세서, supabase_user_id)
       -> 거기서 나온 tenant_id 로 routers 테이블에도 INSERT (도메인, 오리진)
  조회 -> supabase_user_id 로 그 회원이 소유한 고객사 목록 반환

api_key 는 백엔드가 자동 생성한다.
"""
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
