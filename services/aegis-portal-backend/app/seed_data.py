"""
확정된 로그 JSON 스키마(version 3.2)에 맞춘 더미 로그 생성기.
나중에 실제 SOAR 파이프라인이 붙으면 이 파일은 삭제하면 됨.
"""
import random
import uuid
from datetime import datetime, timedelta, timezone

# PostgreSQL tenants 테이블과 느슨하게 맞춘 테넌트 목록
TENANTS = ["enterprise-a", "enterprise-b", "startup-c", "test-company"]

COUNTRIES = [
    ("KR", "Seoul"), ("US", "New York"), ("RU", "Moscow"),
    ("CN", "Beijing"), ("DE", "Berlin"), ("JP", "Tokyo"),
    ("BR", "Sao Paulo"), ("IN", "Mumbai"),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "curl/7.68.0",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "sqlmap/1.7",
]

PATHS_NORMAL = [
    ("GET", "/api/v1/orders/{}", "order"),
    ("GET", "/api/v1/users/{}", "user"),
    ("POST", "/api/v1/orders", "order"),
    ("GET", "/api/v1/products/{}", "product"),
    ("PUT", "/api/v1/users/{}", "user"),
]

PATHS_ATTACK = [
    ("GET", "/.env", "config"),
    ("GET", "/admin", "admin-panel"),
    ("GET", "/api/v1/internal/debug", "shadow-api"),
    ("GET", "/api/v1/orders/{}", "order"),  # BOLA: 남의 리소스 접근
    ("POST", "/api/v1/login", "auth"),
]

TLS_VERSIONS = ["TLSv1.2", "TLSv1.3"]
ACTIONS_BENIGN = ["allowed", "monitored"]


def _rand_hash(prefix: str, length: int = 16) -> str:
    chars = "0123456789abcdef"
    return prefix + "".join(random.choice(chars) for _ in range(length))


def generate_log(is_attack: bool, base_time: datetime, sequence: int) -> dict:
    """단일 로그 문서 1건 생성. is_attack=True면 위험한 패턴으로 채움."""
    country, city = random.choice(COUNTRIES)
    tenant = random.choice(TENANTS)
    user_id = f"user_{random.randint(1000, 9999)}"

    if is_attack:
        method, path_tpl, res_type = random.choice(PATHS_ATTACK)
        risk = round(random.uniform(0.65, 0.99), 2)
        status = random.choice([200, 401, 403, 404])
        is_bola = "orders" in path_tpl and random.random() > 0.4
        is_shadow = "internal" in path_tpl or "admin" in path_tpl
        is_leak = random.random() > 0.7
        action = "blocked" if risk > 0.8 else "monitored"
        rule_id = f"RULE-THREAT-{random.randint(10, 99)}"
        ua = random.choice(USER_AGENTS[-3:])  # 봇/툴 계열
        # BOLA면 요청자와 리소스 소유자가 다름
        owner_id = f"user_{random.randint(1000, 9999)}" if is_bola else user_id
    else:
        method, path_tpl, res_type = random.choice(PATHS_NORMAL)
        risk = round(random.uniform(0.0, 0.3), 2)
        status = random.choice([200, 200, 200, 201])
        is_bola = is_shadow = is_leak = False
        action = random.choice(ACTIONS_BENIGN)
        rule_id = "RULE-SAFE-01"
        ua = random.choice(USER_AGENTS[:2])
        owner_id = user_id

    resource_id = str(random.randint(1000, 9999))
    path = path_tpl.format(resource_id) if "{}" in path_tpl else path_tpl

    return {
        "event": {
            "id": str(uuid.uuid4()),
            "trace_id": f"tr-{random.randint(10**11, 10**12 - 1)}",
            "sequence": sequence,
            # MongoDB에 Date 타입으로 저장 (정렬/범위 쿼리 최적화)
            "timestamp": base_time,
            "version": "3.2",
            "observer": {
                "hostname": f"worker-{random.randint(1, 3):02d}",
                "type": "api-security-engine",
            },
        },
        "source": {
            "ip": "172.18.0.1",
            "nat_ip": f"{random.randint(1,223)}.{random.randint(0,255)}."
                      f"{random.randint(0,255)}.{random.randint(1,254)}",
            "geo": {"country_iso": country, "city_name": city},
            "tls": {
                "version": random.choice(TLS_VERSIONS),
                "ja3_hash": _rand_hash("", 32),
            },
            "user_agent": {"original": ua, "hash": _rand_hash("ua_h")},
        },
        "subject": {
            "user": {
                "id": user_id,
                "role": random.choice(["free_user", "premium_user", "admin"]),
            },
            "auth": {
                "type": "Bearer",
                "is_authenticated": not is_attack or random.random() > 0.5,
                "session_id": f"sess_{random.randint(1000, 9999)}",
            },
            "tenant_id": tenant,
        },
        "http": {
            "request": {
                "method": method,
                "host": "api.aegis3.cloud",
                "path": path,
                "resource": {
                    "type": res_type,
                    "id": resource_id,
                    "owner_id": owner_id,
                },
                "params": "detail=true" if random.random() > 0.5 else "",
                "header_fingerprint": _rand_hash("sh256_"),
                "body_signature": "malicious-pattern" if is_leak else "none",
                "body_size_byte": random.randint(0, 4096),
            },
            "response": {
                "status_code": status,
                "error": {
                    "code": str(status) if status >= 400 else None,
                    "message": "Forbidden" if status == 403 else (
                        "Not Found" if status == 404 else None),
                },
                "latency_ms": random.randint(5, 350),
                "body_size_byte": random.randint(100, 8192),
                "content_type": "application/json",
            },
        },
        "security_analysis": {
            "risk_score": risk,
            "flags": {
                "is_bola": is_bola,
                "is_shadow_api": is_shadow,
                "is_data_leak": is_leak,
            },
            "action": action,
            "rule_id": rule_id,
        },
    }


def generate_logs(count: int = 200) -> list:
    """count개의 로그를 생성. 약 25%는 공격성 트래픽으로 섞음."""
    logs = []
    now = datetime.now(timezone.utc)
    for i in range(count):
        # 최근 7일에 걸쳐 분포
        base_time = now - timedelta(
            minutes=random.randint(0, 7 * 24 * 60)
        )
        is_attack = random.random() < 0.25
        logs.append(generate_log(is_attack, base_time, sequence=i % 50))
    return logs
