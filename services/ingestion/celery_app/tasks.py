from celery_app import celery_app, redis_client
import time

@celery_app.task(bind=True, max_retries=3)
def process_security_log(self, log_data):
    """
    단일 로그 데이터를 처리하는 Task
    (파싱, 정규화, 위협 인텔리전스 연동 등 SOAR의 핵심 전처리 수행)
    """
    import json
    import requests
    
    try:
        print(f"[Worker] 로그 처리 시작: {log_data}")
        time.sleep(1) 
        
        # 1. 로그 위협 분석 및 대응 엔진 보고 로직
        log_json = None
        if isinstance(log_data, str):
            try:
                log_json = json.loads(log_data)
            except json.JSONDecodeError:
                # 단순 문자열인 경우 테스트 페이로드(SQLi, XSS) 여부 판별
                if "OR" in log_data or "'" in log_data:
                    log_json = {"attacker_ip": "127.0.0.1", "event_type": "SQL Injection Test"}
                elif "<script>" in log_data:
                    log_json = {"attacker_ip": "127.0.0.1", "event_type": "XSS Test"}
        elif isinstance(log_data, dict):
            log_json = log_data

        if log_json:
            attacker_ip = log_json.get("attacker_ip")
            event_type = log_json.get("event_type")
            
            # WAF 탐지 또는 허니팟 매칭 등 자동 차단/대응 필요 시
            if attacker_ip and event_type:
                print(f"[Worker] 🚨 위협 탐지! 대응 엔진(analyzer)으로 보고 전송: IP={attacker_ip}, Type={event_type}")
                try:
                    response = requests.post(
                        "http://analyzer:5000/api/v1/report",
                        json={"ip": attacker_ip, "type": event_type},
                        timeout=5
                    )
                    print(f"[Worker] 대응 엔진 응답: {response.status_code} - {response.json()}")
                except Exception as req_err:
                    print(f"[Error] 대응 엔진(analyzer) 호출 실패: {req_err}")

        print(f"[Worker] 로그 처리 완료")
        return {"status": "success", "data": log_data}
    except Exception as exc:
        print(f"[Error] 로그 처리 실패: {exc}")
        # 실패 시 재시도 로직 (SOAR에서는 데이터 유실 방지가 중요함)
        raise self.retry(exc=exc, countdown=5)

@celery_app.task
def consume_logs_from_redis_queue():
    """
    외부 시스템이 'aegis:security-events'라는 Redis List에 로그를 쌓는다고 가정할 때,
    이를 100개씩 주기적으로 꺼내와서(Consume) 처리 큐로 넘기는 Task
    (주기적 실행을 위해 Celery Beat와 연동 가능)
    """
    queue_name = "aegis:security-events"
    batch_size = 100
    
    logs_processed = 0
    while logs_processed < batch_size:
        # RPOP을 사용하여 큐에서 데이터 꺼내기 (오래된 것부터)
        log_raw = redis_client.rpop(queue_name)
        if not log_raw:
            break # 큐가 비었으면 중단
            
        # 꺼낸 로그를 처리하는 개별 Task 비동기 호출
        process_security_log.delay(log_raw)
        logs_processed += 1
        
    return f"{logs_processed}개의 로그를 큐에서 꺼내 처리 작업에 할당했습니다."