# =========================
# config.py
# Risk Score 기본 설정값 / 탐지 패턴 관리
#
# [튜닝] 임계값은 모두 환경변수로 덮어쓸 수 있다 (미설정 시 아래 기본값 = 기존 값 그대로).
#   k6 부하 결과로 조정할 때 코드 수정 없이 docker-compose environment 만 바꾸면 된다.
#   예) NORMAL_P95_PER_MINUTE=120, SCAN_FAST_LOW=20
# =========================

import os


def _env_int(name, default):
    """정수 환경변수 읽기. 비어 있거나 숫자가 아니면 기본값을 쓴다(엔진이 죽지 않도록)."""
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        print(f"[config] {name}={raw!r} 는 정수가 아님 — 기본값 {default} 사용")
        return default


# 빠른 이상행위 관찰 구간
FAST_WINDOW_SECONDS = _env_int("FAST_WINDOW_SECONDS", 60)

# 느린 스캔 보완 구간
SLOW_WINDOW_SECONDS = _env_int("SLOW_WINDOW_SECONDS", 600)

# Alert Event 생성 기준
# 80점 초과면 CRITICAL로 보고 Alert 생성
ALERT_THRESHOLD = _env_int("ALERT_THRESHOLD", 80)

# 정상 사용자 p95 요청량 초기값
# 실제 운영에서는 고객사별 정상 로그 기반으로 다시 계산 가능
NORMAL_P95_PER_MINUTE = _env_int("NORMAL_P95_PER_MINUTE", 50)


# =========================
# detector 개별 임계값 (기본값 = 기존 하드코딩 값)
# =========================

# 경로 열거: 고유 404 path 개수
SCAN_FAST_LOW = _env_int("SCAN_FAST_LOW", 15)     # 60초 → R-SCAN-001
SCAN_FAST_HIGH = _env_int("SCAN_FAST_HIGH", 30)   # 60초 → R-SCAN-002
SCAN_SLOW = _env_int("SCAN_SLOW", 50)             # 10분 → R-SCAN-003

# BOLA/IDOR: 권한 없는 고유 객체 ID 개수 (60초)
BOLA_LOW = _env_int("BOLA_LOW", 3)                # R-BOLA-001
BOLA_HIGH = _env_int("BOLA_HIGH", 10)             # R-BOLA-002

# 민감 경로: 카테고리 종류 수 (60초)
ASSET_CATEGORY_MIN = _env_int("ASSET_CATEGORY_MIN", 3)  # R-ASSET-002

# 요청량: max(최소값, p95 × 배수) / 60초
RATE_LOW_MIN = _env_int("RATE_LOW_MIN", 100)      # R-RATE-001
RATE_LOW_MULT = _env_int("RATE_LOW_MULT", 3)
RATE_HIGH_MIN = _env_int("RATE_HIGH_MIN", 200)    # R-RATE-002
RATE_HIGH_MULT = _env_int("RATE_HIGH_MULT", 6)

# 인증/토큰 남용 (60초)
AUTH_LOGIN_FAIL_MIN = _env_int("AUTH_LOGIN_FAIL_MIN", 10)  # R-AUTH-001
AUTH_JWT_ERROR_MIN = _env_int("AUTH_JWT_ERROR_MIN", 10)    # R-AUTH-002
AUTH_RECOVERY_MIN = _env_int("AUTH_RECOVERY_MIN", 5)       # R-AUTH-003

# 상태 저장소 정리: N건 분석마다 SLOW_WINDOW 보다 오래된 IP/세션 키 제거 (메모리 누수 방지)
STATE_PURGE_EVERY = _env_int("STATE_PURGE_EVERY", 1000)


# =========================
# 민감 경로 패턴
# =========================

SENSITIVE_RULES = [
    ("환경변수/설정", r"^/\.env($|[./_-])"),
    ("환경변수/설정", r"^/(config|settings|application)\.(json|yml|yaml|properties|php|py)$"),
    ("환경변수/설정", r"^/web\.config$"),

    ("소스/버전관리", r"^/\.(git|svn|hg|bzr)(/|$)"),
    ("소스/버전관리", r"^/CVS(/|$)"),

    ("백업/덤프", r"^/(backup|dump|database|db|site|www).*\.(zip|tar|gz|sql|bak|old|save|swp)$"),
    ("백업/덤프", r".*\.(bak|old|save|swp)$"),

    ("관리자 페이지", r"^/(admin|administrator|manager|console|cpanel|dashboard|backend|manage)(/|$)"),

    ("DB/관리도구", r"^/(phpmyadmin|pma|adminer|mysql|pgadmin|mongo-express|redis-commander)(/|$)"),

    ("API 문서", r"^/(swagger|swagger-ui|swagger-ui\.html|api-docs|openapi\.json|v2/api-docs|v3/api-docs|docs|redoc)(/|$)"),

    ("디버그/운영", r"^/(debug|debug/vars|actuator|actuator/env|actuator/health|actuator/metrics|server-status|status|metrics|prometheus)(/|$)"),

    ("GraphQL", r"^/(graphql|graphiql|playground|altair)(/|$)"),

    ("로그 파일", r"^/(logs?|access\.log|error\.log|debug\.log|app\.log|laravel\.log)(/|$)"),

    ("프론트 디버그", r".*\.js\.map$"),

    ("CI/CD", r"^/(\.github|\.gitlab-ci\.yml|Jenkinsfile|jenkins|teamcity|circleci|\.circleci)(/|$)"),

    ("컨테이너/인프라", r"^/(Dockerfile|docker-compose\.yml|\.dockerignore|k8s|kubernetes|helm|terraform\.tfstate|main\.tf)(/|$)"),

    ("클라우드/키", r"^/(credentials|aws/credentials|\.aws/credentials|serviceAccount\.json|firebase\.json|gcp-key\.json)(/|$)"),

    ("CMS/WordPress", r"^/(wp-admin|wp-login\.php|xmlrpc\.php|wp-config\.php|wp-content)(/|$)"),

    ("Java/Tomcat", r"^/(manager/html|host-manager/html|jmx-console|web-console)(/|$)"),

    ("Laravel/PHP", r"^/(vendor/phpunit|storage/logs/laravel\.log|artisan)(/|$)"),

    ("Node.js", r"^/(package\.json|package-lock\.json|yarn\.lock|node_modules|server\.js)(/|$)"),

    ("Python/Django", r"^/(settings\.py|manage\.py|requirements\.txt|__pycache__)(/|$)"),

    ("Java/Spring", r"^/(pom\.xml|gradle\.properties|actuator/heapdump)(/|$)"),
]


# =========================
# Payload 우회 패턴
# =========================

DOUBLE_ENCODING_PATTERNS = [
    r"%25[0-9a-fA-F]{2}",
    r"%252e",
    r"%252f",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"\.\.%2f",
    r"\.\.%5c",   # [수정] 점 이스케이프 누락 → 'ab%5c' 같은 평문도 매칭되던 오탐
]

SSRF_PATTERNS = [
    r"169\.254\.169\.254",
    r"127\.0\.0\.1",
    r"localhost",
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}",
    r"192\.168\.\d{1,3}\.\d{1,3}",
    r"metadata\.google\.internal",
]

COMMAND_INJECTION_PATTERNS = [
    r"(;|\||&&)\s*(id|whoami|uname|cat|curl|wget|bash|sh)\b",
    r"`[^`]+`",
    r"\$\([^)]+\)",
]