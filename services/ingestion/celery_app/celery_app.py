import os
from celery import Celery
import redis

# 환경 변수에서 URL을 가져오고, 없으면 localhost(로컬 테스트용) 사용
BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
BACKEND_URL = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Celery 앱 초기화
celery_app = Celery(
    "soar_tasks",
    broker=BROKER_URL,
    backend=BACKEND_URL
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='Asia/Seoul',
    enable_utc=False,
)

# Beat 스케줄: proxy 가 Redis 에 LPUSH 한 보안 이벤트를 주기적으로 자동 소비.
# 주기는 BEAT_CONSUME_INTERVAL(초)로 조정 가능, 기본 2초.
celery_app.conf.beat_schedule = {
    'consume-redis-queue': {
        'task': 'tasks.consume_logs_from_redis_queue',
        'schedule': float(os.getenv("BEAT_CONSUME_INTERVAL", "2.0")),
    },
}

# 직접 Redis 큐를 제어해야 할 경우를 위한 클라이언트 (URL에서 직접 파싱)
redis_client = redis.from_url(REDIS_URL, decode_responses=True)