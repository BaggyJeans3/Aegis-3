from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from tasks import process_security_log, consume_logs_from_redis_queue
from celery_app import redis_client

app = FastAPI(title="SOAR Data Ingestion API")

class LogPayload(BaseModel):
    source: str
    event_type: str
    raw_data: str

@app.post("/api/v1/webhook/logs")
async def receive_log_webhook(payload: LogPayload):
    """Webhook 형태로 들어오는 실시간 로그를 수신하여 Celery로 비동기 처리"""
    # delay()를 통해 백그라운드 워커에 작업 전달
    task = process_security_log.delay(payload.model_dump())
    return {"message": "Log accepted", "task_id": task.id}

@app.post("/api/v1/tasks/consume")
async def trigger_consume():
    """수동으로 Redis 큐 Consume 작업을 트리거"""
    task = consume_logs_from_redis_queue.delay()
    return {"message": "Consume task triggered", "task_id": task.id}

@app.get("/api/v1/health")
async def health_check():
    """Redis 및 API 상태 체크"""
    redis_ping = redis_client.ping()
    return {"api": "ok", "redis": redis_ping}