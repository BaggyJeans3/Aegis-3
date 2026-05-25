from celery_app import celery_app, redis_client
import json
import os
import requests
from datetime import datetime
from pymongo import MongoClient


# ============================================================
# Worker 설정
# ============================================================

# Redis Queue 이름
# Proxy가 Redis에 LPUSH하는 키와 반드시 같아야 함
REDIS_QUEUE_NAME = os.getenv("REDIS_QUEUE_NAME", "aegis:security-events")

# Risk Score Engine 주소
# Docker 내부 통신에서는 localhost가 아니라 서비스명을 써야 함
# docker-compose에서 risk score 엔진 서비스명을 detection-engine으로 만들면 아래 기본값 그대로 사용
RISK_ANALYZER_URL = os.getenv(
    "RISK_ANALYZER_URL",
    "http://detection-engine:5000/analyze"
)

# MongoDB 저장 설정
MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://mongodb:27017/aegis_logs"
)

MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "aegis_logs")
MONGO_COLLECTION_NAME = os.getenv("MONGO_COLLECTION_NAME", "security_logs")


def normalize_redis_log(log_data):
    """
    Redis에서 꺼낸 이벤트를 dict로 변환한다.

    Redis rpop 결과는 str 또는 bytes일 수 있고,
    Webhook 테스트에서는 dict로 들어올 수도 있어서 모두 처리한다.
    """
    if isinstance(log_data, bytes):
        log_data = log_data.decode("utf-8")

    if isinstance(log_data, str):
        return json.loads(log_data)

    if isinstance(log_data, dict):
        return log_data

    raise ValueError(f"Unsupported log_data type: {type(log_data)}")


def get_mongo_collection():
    """
    MongoDB collection 객체를 반환한다.
    """
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB_NAME]
    return db[MONGO_COLLECTION_NAME]


def build_mongo_document(raw_event, analyzer_result):
    """
    MongoDB에 저장할 최종 로그 문서를 만든다.

    raw_event:
    - Proxy가 Redis에 넣은 원본 이벤트

    security_analysis:
    - Risk Score Engine이 계산한 결과
    """
    detection_result = analyzer_result.get("detection_result", {})
    alert_event = analyzer_result.get("alert_event")

    return {
        "event_id": raw_event.get("event_id"),
        "trace_id": raw_event.get("trace_id"),

        "raw_event": raw_event,

        "security_analysis": {
            "status": "analyzed",
            "risk_score": detection_result.get("risk_score"),
            "level": detection_result.get("level"),
            "alert": detection_result.get("alert"),
            "rule_hits": detection_result.get("rule_hits", []),
            "reasons": detection_result.get("reasons", []),
            "analysis_profile": detection_result.get(
                "analysis_profile",
                raw_event.get("analysis_profile")
            ),
            "action_on_match": detection_result.get(
                "action_on_match",
                raw_event.get("action_on_match")
            ),
        },

        # 지금 단계에서는 LLM/대응 호출은 보류.
        # 나중에 HIGH/CRITICAL일 때 analyzer.js /api/v1/report로 넘기면 됨.
        "llm": {
            "sent": False,
            "reason": "LLM/SOAR response is deferred"
        },

        "alert_event": alert_event,

        "created_at": datetime.utcnow().isoformat() + "Z"
    }


@celery_app.task(bind=True, max_retries=3)
def process_security_log(self, log_data):
    """
    Redis에서 꺼낸 단일 이벤트 로그를 처리하는 Task.

    기존 구조:
    Redis 이벤트 → analyzer:5000/api/v1/report → Slack/CF/Email 대응

    수정 구조:
    Redis 이벤트 → Risk Score Engine /analyze → MongoDB 저장
    """
    try:
        raw_event = normalize_redis_log(log_data)
        print(f"[Worker] Redis 이벤트 처리 시작: {raw_event}")

        # ------------------------------------------------------------
        # 1. Risk Score Engine으로 분석 요청
        # ------------------------------------------------------------
        try:
            response = requests.post(
                RISK_ANALYZER_URL,
                json=raw_event,
                timeout=5
            )
            response.raise_for_status()
            analyzer_result = response.json()

            print(
                "[Worker] Risk Score 응답 수신: "
                f"{response.status_code} - {analyzer_result}"
            )

        except Exception as req_err:
            print(f"[Error] Risk Score Engine 호출 실패: {req_err}")
            raise req_err

        # ------------------------------------------------------------
        # 2. MongoDB에 최종 로그 저장
        # ------------------------------------------------------------
        try:
            mongo_doc = build_mongo_document(
                raw_event=raw_event,
                analyzer_result=analyzer_result
            )

            collection = get_mongo_collection()
            insert_result = collection.insert_one(mongo_doc)

            print(f"[Worker] MongoDB 저장 완료: inserted_id={insert_result.inserted_id}")

        except Exception as mongo_err:
            print(f"[Error] MongoDB 저장 실패: {mongo_err}")
            raise mongo_err

        print("[Worker] 로그 처리 완료")

        return {
            "status": "success",
            "event_id": raw_event.get("event_id"),
            "risk_score": analyzer_result.get("detection_result", {}).get("risk_score"),
            "level": analyzer_result.get("detection_result", {}).get("level"),
        }

    except Exception as exc:
        print(f"[Error] 로그 처리 실패: {exc}")
        raise self.retry(exc=exc, countdown=5)


@celery_app.task
def consume_logs_from_redis_queue():
    """
    Redis List에 쌓인 Proxy 이벤트를 꺼내 Celery Task로 넘긴다.

    Proxy:
    LPUSH aegis:security-events

    Worker:
    RPOP aegis:security-events

    이렇게 하면 오래된 이벤트부터 처리된다.
    """
    queue_name = REDIS_QUEUE_NAME
    batch_size = 100

    logs_processed = 0

    while logs_processed < batch_size:
        log_raw = redis_client.rpop(queue_name)

        if not log_raw:
            break

        process_security_log.delay(log_raw)
        logs_processed += 1

    message = f"{logs_processed}개의 로그를 Redis 큐에서 꺼내 처리 작업에 할당했습니다."
    print(f"[Worker] {message}")

    return message