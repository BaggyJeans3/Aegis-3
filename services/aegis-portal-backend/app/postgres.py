"""
PostgreSQL 연결 관리 (고객사 정보 DB).

MongoDB(database.py)가 로그를 담당하듯, 이 파일은 PostgreSQL을 담당.
  - tenants 테이블: 고객사 정보
  - routers 테이블: 라우팅 규칙

접속 정보는 환경변수로 주입:
  - PC 로컬 실행: .env 파일 (SSH 터널이라 POSTGRES_HOST=localhost)
  - EC2 docker-compose 실행: compose environment (POSTGRES_HOST=aegis-postgres)
"""
import os
import asyncpg

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# docker-compose.yml 의 postgres-db 설정과 동일하게 맞춤
PG_USER = os.getenv("DB_USER", "aegis_admin")
PG_PASSWORD = os.getenv("POSTGRES_PASSWORD", "")
PG_HOST = os.getenv("POSTGRES_HOST", "aegis-postgres")
PG_PORT = os.getenv("POSTGRES_PORT", "5432")
PG_DB = os.getenv("DB_NAME", "aegis_proxy")


class PgDatabase:
    pool: asyncpg.Pool = None


pg = PgDatabase()


async def connect_to_postgres():
    """커넥션 풀 생성. 앱 시작 시 1회 호출."""
    pg.pool = await asyncpg.create_pool(
        user=PG_USER,
        password=PG_PASSWORD,
        host=PG_HOST,
        port=int(PG_PORT),
        database=PG_DB,
        min_size=1,
        max_size=5,
    )


async def close_postgres_connection():
    """앱 종료 시 커넥션 풀 정리."""
    if pg.pool:
        await pg.pool.close()


def get_pool() -> asyncpg.Pool:
    """커넥션 풀 핸들 반환."""
    return pg.pool
