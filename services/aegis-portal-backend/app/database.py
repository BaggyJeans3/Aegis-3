"""
MongoDB 연결 관리.
접속 정보는 환경변수로 주입받음.
  - PC에서 실행: 같은 폴더의 .env 파일에서 자동 로드
  - EC2 docker-compose에서 실행: compose의 environment로 주입

[변경 사항]
  - 컬렉션: traffic_logs (soar 시스템이 직접 INSERT)
  - 인덱스: 새 스키마 (raw_event.tenant_id, raw_event.timestamp 등) 기준
"""
import os
from urllib.parse import quote_plus
from motor.motor_asyncio import AsyncIOMotorClient

try:
    # PC 로컬 실행 시 .env 파일을 읽음. 없으면 그냥 넘어감.
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# 로컬 PC 실행 시: MONGO_HOST=localhost (SSH 터널)
# EC2 docker-compose 실행 시: MONGO_HOST=aegis-mongodb (컨테이너 이름)
MONGO_USER = os.getenv("MONGO_USER", "aegis_user")
MONGO_PASSWORD = os.getenv("MONGO_PASSWORD", "")
MONGO_HOST = os.getenv("MONGO_HOST", "aegis-mongodb")
MONGO_PORT = os.getenv("MONGO_PORT", "27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "aegis_logs")

# 사용자명/비밀번호에 @ : / # ? 등 특수문자가 있어도 URI가 깨지지 않도록
# URL 인코딩 처리. (인코딩 안 하면 인증 실패의 원인이 됨)
_user = quote_plus(MONGO_USER)
_password = quote_plus(MONGO_PASSWORD)

MONGO_URI = (
    f"mongodb://{_user}:{_password}"
    f"@{MONGO_HOST}:{MONGO_PORT}/?authSource=admin"
)

# soar 시스템이 INSERT 하는 컬렉션 이름
LOG_COLLECTION = "traffic_logs"


class Database:
    client: AsyncIOMotorClient = None


db = Database()


def get_collection():
    """로그 컬렉션 핸들 반환."""
    return db.client[MONGO_DB_NAME][LOG_COLLECTION]


async def connect_to_mongo():
    db.client = AsyncIOMotorClient(MONGO_URI)
    # 새 soar 스키마 기준 인덱스 생성 (없으면 만들고 있으면 무시)
    coll = get_collection()
    await coll.create_index("raw_event.tenant_id")
    await coll.create_index("raw_event.timestamp")
    await coll.create_index("created_at")
    await coll.create_index("security_analysis.action_on_match")
    await coll.create_index("security_analysis.risk_score")
    await coll.create_index("security_analysis.level")


async def close_mongo_connection():
    if db.client:
        db.client.close()