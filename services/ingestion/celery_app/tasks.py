import os
import json
import time
import requests
from datetime import datetime
from urllib.parse import quote_plus
from pymongo import MongoClient

from celery_app import celery_app, redis_client
from ai_engine import generate_waf_rule_with_feedback

import re
import hashlib


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

# AI 룰 생성 임계값 및 Nginx 사이드카(룰 주입) 엔드포인트
AI_RULE_THRESHOLD = int(os.getenv("AI_RULE_THRESHOLD", "80"))
NGINX_SIDECAR_URL = os.getenv(
    "NGINX_SIDECAR_URL",
    "http://nginx:4000/api/v1/rules/inject"
)


# ============================================================
# [Aegis-3 SOAR] 작업 7 — 공격 클러스터링
# 비슷한 공격 패턴은 LLM 재호출 없이 캐시된 결과 재사용
# ============================================================

CLUSTER_TTL_SECONDS = int(os.getenv("CLUSTER_TTL_SECONDS", "300"))  # 5분


def normalize_attack_log(raw_event: dict) -> str:
    """
    공격 로그에서 IP·세션·타임스탬프 등 변동 요소를 제거하고
    공격 패턴의 본질만 남긴 정규화 문자열을 반환한다.
    """
    method = (raw_event.get("method") or "").upper()
    path = (raw_event.get("path") or "").lower()
    query = (raw_event.get("query") or "").lower()
    body = (raw_event.get("body") or "").lower()
    ua = (raw_event.get("headers", {}).get("user-agent") or "").lower()

    text = f"{method} {path}?{query} body={body} ua={ua}"

    # 숫자 → N  (id=123, id=999 같은 변동값 통일)
    text = re.sub(r"\d+", "N", text)
    # 긴 16진수/UUID → X  (세션 토큰, 해시값 통일)
    text = re.sub(r"[a-f0-9]{16,}", "X", text)
    # 연속 공백 정리
    text = re.sub(r"\s+", " ", text).strip()

    return text


def compute_cluster_key(raw_event: dict) -> str:
    """정규화된 공격 로그의 SHA256 앞 16자로 클러스터 키 생성."""
    normalized = normalize_attack_log(raw_event)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"aegis:cluster:{digest}"


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


def _build_mongo_uri():
    """
    MONGO_USER / MONGO_PASSWORD 가 따로 주어지면 패스워드를 URL-encode 해서 URI 를 조립한다.
    docker-compose 가 ${VAR} 치환 시 URL-escape 하지 않기 때문에, 패스워드에 @ : / ? # 등이
    들어있으면 MONGO_URI 그대로는 pymongo 가 거절한다. 별도 컴포넌트를 받아 안전하게 만든다.
    """
    user = os.getenv("MONGO_USER")
    password = os.getenv("MONGO_PASSWORD")
    if user and password:
        host = os.getenv("MONGO_HOST", "mongodb")
        port = os.getenv("MONGO_PORT", "27017")
        db_name = os.getenv("MONGO_DB_NAME", "aegis_logs")
        auth_source = os.getenv("MONGO_AUTH_SOURCE", "admin")
        return (
            f"mongodb://{quote_plus(user)}:{quote_plus(password)}"
            f"@{host}:{port}/{db_name}?authSource={auth_source}"
        )
    return MONGO_URI


def get_mongo_collection():
    """
    MongoDB collection 객체를 반환한다.
    """
    client = MongoClient(_build_mongo_uri())
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


def _build_coraza_rule(rule: dict) -> str:
    """AI가 반환한 dict를 Coraza SecRule 한 줄로 직렬화"""
    regex = rule.get("regex", "").replace('"', '\\"')
    name = rule.get("rule_name", "AI_GENERATED").replace('"', '\\"')
    # 룰 ID 충돌 방지:
    # - 900000~999999 는 OWASP CRS 가 점유 (REQUEST/RESPONSE 9xx 시리즈)
    # - 100~100090 은 aegis3-custom-rules.conf 가 사용
    # AI 룰은 32-bit 정수 한계(약 21억) 안의 2,000,000,000~2,099,999,999 범위로 격리.
    # ms 정밀도 + 1억 modulo → 약 11.5년 cycle, 같은 ms 동시 발화 외엔 자체 충돌 없음.
    rule_id = 2_000_000_000 + (int(time.time() * 1000) % 100_000_000)
    return (
        f'SecRule REQUEST_URI|ARGS|REQUEST_BODY "@rx {regex}" '
        f'"id:{rule_id},phase:2,deny,status:403,msg:\'{name}\',log"'
    )


def _inject_rule_to_nginx(rule: dict) -> None:
    """생성된 WAF 룰을 Nginx 사이드카로 전송"""
    try:
        rule_str = _build_coraza_rule(rule)
        resp = requests.post(
            NGINX_SIDECAR_URL,
            json={"rule": rule_str},
            timeout=5,
        )
        print(f"[Worker] WAF 룰 주입 응답: {resp.status_code} - {resp.text[:200]}")
    except Exception as inj_err:
        print(f"[Error] Nginx 사이드카 룰 주입 실패: {inj_err}")


@celery_app.task(bind=True, max_retries=3)
def process_security_log(self, log_data):
    """
    Redis에서 꺼낸 단일 이벤트 로그를 처리하는 Task.

    Redis 이벤트 → Risk Score Engine /analyze → MongoDB 저장
                → (risk_score ≥ AI_RULE_THRESHOLD) AI WAF 룰 생성 → Nginx 사이드카 주입
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

        # ------------------------------------------------------------
        # 3. 고위험 시 AI WAF 룰 생성 → Nginx 사이드카로 주입
        # ------------------------------------------------------------
        detection_result = analyzer_result.get("detection_result", {})
        risk_score = int(detection_result.get("risk_score") or 0)
        if risk_score >= AI_RULE_THRESHOLD:
            # ──────────────────────────────────────────────────────────
            # [Aegis-3 SOAR] IP 평판 — 작업 6-A
            # LLM 호출 전 블랙리스트 체크: 24시간 내 이미 악성 판정된 IP면
            # LLM 재호출 없이 즉시 스킵 (비용·할당량 절감)
            # Redis 장애 시 fail-open — 정상 분석은 계속 진행
            # ──────────────────────────────────────────────────────────
            ip = raw_event.get("ip")
            blacklist_key = f"aegis:blacklist:{ip}" if ip and ip != "unknown" else None

            if blacklist_key:
                try:
                    if redis_client.exists(blacklist_key):
                        try:
                            redis_client.incr("aegis:stats:llm_skipped")
                        except Exception:
                            pass
                        print(f"[Worker] 🛑 IP {ip} blacklist hit — LLM 호출 skip")
                        return {
                            "status": "success",
                            "event_id": raw_event.get("event_id"),
                            "risk_score": risk_score,
                            "level": detection_result.get("level"),
                            "llm_skipped": True,
                            "reason": "ip_blacklisted",
                        }
                except Exception as redis_err:
                    print(f"[Worker] ⚠️ Redis EXISTS 실패: {redis_err} — fail-open으로 LLM 진행")

            # ──────────────────────────────────────────────────────────
            # [Aegis-3 SOAR] 작업 7 — 공격 클러스터 캐시 체크
            # 정규화된 패턴이 5분 내 이미 처리됐으면 LLM 재호출 없이 결과 재사용
            # Redis 장애 시 fail-open
            # ──────────────────────────────────────────────────────────
            cluster_key = compute_cluster_key(raw_event)
            try:
                cached_rule_name = redis_client.get(cluster_key)
                if cached_rule_name:
                    try:
                        redis_client.incr("aegis:stats:cluster_skipped")
                    except Exception:
                        pass
                    print(f"[Worker] ♻️ 클러스터 캐시 hit ({cluster_key}) — LLM 호출 skip, 기존 룰 재사용: {cached_rule_name}")
                    return {
                        "status": "success",
                        "event_id": raw_event.get("event_id"),
                        "risk_score": risk_score,
                        "level": detection_result.get("level"),
                        "llm_skipped": True,
                        "reason": "cluster_cache_hit",
                        "cached_rule": cached_rule_name,
                    }
            except Exception as redis_err:
                print(f"[Worker] ⚠️ 클러스터 캐시 조회 실패: {redis_err} — fail-open으로 LLM 진행")

            # LLM 호출 (기존 로직)
            print(f"[Worker] 🧠 risk_score={risk_score} ≥ {AI_RULE_THRESHOLD}, AI 룰 생성 시작")
            ai_rule = generate_waf_rule_with_feedback(raw_event)

            # ──────────────────────────────────────────────────────────
            # [Aegis-3 SOAR] 작업 7 — 클러스터 캐시 저장
            # 다음 5분 안에 같은 패턴이 다시 오면 LLM 재호출 회피
            # ──────────────────────────────────────────────────────────
            if ai_rule and ai_rule.get("rule_name"):
                try:
                    redis_client.setex(cluster_key, CLUSTER_TTL_SECONDS, ai_rule.get("rule_name"))
                    print(f"[Worker] 📌 클러스터 캐시 저장 ({cluster_key}, TTL {CLUSTER_TTL_SECONDS}s): {ai_rule.get('rule_name')}")
                except Exception as redis_err:
                    print(f"[Worker] ⚠️ 클러스터 캐시 저장 실패: {redis_err}")

            # LLM 호출 후 IP를 24h 블랙리스트 등록 (성공/실패 모두)
            # — Proxy 1차 차단 미들웨어가 다음 요청을 즉시 끊을 수 있도록
            if blacklist_key:
                try:
                    redis_client.setex(blacklist_key, 86400, "1")
                    print(f"[Worker] 🔒 IP {ip} blacklist 등록 (TTL 24h)")
                except Exception as redis_err:
                    print(f"[Worker] ⚠️ Redis SETEX 실패: {redis_err}")

            if ai_rule and ai_rule.get("regex"):
                print(f"[Worker] ✅ AI 룰 생성됨: {ai_rule.get('rule_name')} (confidence={ai_rule.get('confidence_score')})")
                _inject_rule_to_nginx(ai_rule)
            else:
                print(f"[Worker] ⚠️ AI 룰 생성 실패(반환 None) — 주입 건너뜀")

        print("[Worker] 로그 처리 완료")

        return {
            "status": "success",
            "event_id": raw_event.get("event_id"),
            "risk_score": risk_score,
            "level": detection_result.get("level"),
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