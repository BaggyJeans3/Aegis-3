# =========================
# config.py
# Risk Score 기본 설정값 / 탐지 패턴 관리
# =========================

# 빠른 이상행위 관찰 구간
FAST_WINDOW_SECONDS = 60

# 느린 스캔 보완 구간
SLOW_WINDOW_SECONDS = 600

# Alert Event 생성 기준
# 80점 초과면 CRITICAL로 보고 Alert 생성
ALERT_THRESHOLD = 80

# 정상 사용자 p95 요청량 초기값
# 실제 운영에서는 고객사별 정상 로그 기반으로 다시 계산 가능
NORMAL_P95_PER_MINUTE = 50


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
    r"..%5c",
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