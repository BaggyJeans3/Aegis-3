# 🛡️ Aegis-3: Intelligent API Security Gateway & SOAR Orchestrator

**Aegis-3**는 **Nginx + Coraza WAF** 모듈식 방화벽 레이어와 **Express.js 지능형 프록시**, **Celery 기반 SOAR 파이프라인(Queue-Worker + Beat 자동 스케줄러)**, **Risk Score Engine 정량 분석기**, **Gemini LLM 기반 AI WAF 룰 자동 생성기**, **Nginx 사이드카 동적 룰 주입기**, 그리고 **실시간 위협 대응 엔진(Analyzer)** 을 결합한 통합 지능형 API 보안 게이트웨이 및 자동 대응 플랫폼입니다.

외부 침입 탐지 및 차단은 물론, 민감 정보 자동 마스킹, 내부 유입 로그의 분산 비동기 전처리, Risk Score 정량 평가, **AI 가 공격 로그를 분석해 PCRE 정규식 WAF 룰을 자동 생성·주입하여 즉시 차단**까지, 그리고 API를 통한 **Slack 알림, Cloudflare IP 영구 차단, 긴급 이메일 전송**까지 일관된 오케스트레이션을 제공합니다.

---

## 현재 시스템 아키텍처 및 데이터 흐름 (진행중)

```text
  [공격자/사용자 요청]
          │
          ▼
┌──────────────────────────────────────────────────────┐
│                  Nginx + Coraza WAF                  │ (Port 80)
│  ├─ ngx_http_coraza_module                           │ (CRS + custom + AI dynamic 룰 차단)
│  ├─ /etc/nginx/rules/dynamic.conf                    │ (AI 가 적재한 SecRule 영속 저장)
│  ├─ ngx_http_sub_module                              │ (전화번호/주민번호 정규식 마스킹)
│  └─ Sidecar API :4000  /api/v1/rules/inject          │ (Worker → 룰 주입 + nginx -s reload)
└──────────────────────────┬───────────────────────────┘
                           │ (proxy_pass)
                           ▼
┌──────────────────────────────────────────────────────┐
│                   Aegis-3 Proxy                      │ (Port 3000, Express)
│  ├─ PostgreSQL 기반 동적 라우팅                       │
│  └─ honeypot / block / decoy 응답                     │
└──────────────────────────┬───────────────────────────┘
                           │ (LPUSH aegis:security-events)
                           ▼
┌──────────────────────────────────────────────────────┐
│                     Redis Queue                      │
└──────────────────────────┬───────────────────────────┘
                           │ (Celery Beat: 2초마다 자동 RPOP)
                           ▼
┌──────────────────────────────────────────────────────┐
│              Celery Worker (+ Beat 내장)              │
│   process_security_log 비동기 태스크                  │
└─────┬───────────────────┬───────────────────┬────────┘
      │ (Risk 분석)         │ (저장)              │ (high-risk만)
      ▼                   ▼                   ▼
┌────────────────┐ ┌────────────────┐ ┌────────────────────────┐
│ Detection      │ │   MongoDB      │ │  ai_engine             │
│ Engine :5000   │ │ aegis_logs/    │ │  Google Gemini 2.5     │
│ /analyze       │ │ security_logs  │ │  + JSON 강제 + 피드백  │
│ risk_score+    │ │                │ │   루프 + 정규식 검증    │
│ rule_hits      │ │                │ │                        │
└────────────────┘ └────────────────┘ └───────────┬────────────┘
                                                  │ (POST 사이드카)
                                                  ▼
                                       (Coraza dynamic.conf 적재
                                        → nginx reload → 즉시 차단)

      [Analyzer 경로 — Slack/CF/Email 알림은 향후 연동 예정]
┌──────────────────────────────────────────────────────┐
│        Aegis-3 Analyzer (Port 3000/5000, Node.js)    │
│  ├─ Cloudflare WAF Block API                         │
│  ├─ Slack Bolt App  (#security-alerts)               │
│  └─ nodemailer (SMTP HTML 보고서)                     │
└──────────────────────────────────────────────────────┘

      [대시보드 조회 경로 — 고객사/관리자용]
   MongoDB(로그) ─┐
                 ▼
┌──────────────────────────────────────────────────────┐
│      Aegis Portal Backend (Port 8001, FastAPI)       │
│  ├─ Supabase JWT 인증 (JWKS 검증 + role 판별)         │
│  ├─ 테넌트 격리 (admin=전체 / customer=본인 tenant)   │
│  ├─ 로그/통계/SSE 실시간 스트림 조회                  │
│  └─ 고객사(tenant) 등록·조회 (PostgreSQL)             │
└──────────────────────────────────────────────────────┘
                 ▲
   PostgreSQL(고객사) ─┘
```

---

## ✨ 주요 기능

1. **지능형 WAF 방어 (Nginx + Coraza + OWASP CRS)**
   - Coraza WAF가 Nginx 동적 모듈로 삽입되어 SQL Injection, XSS, Path Traversal 등의 위협을 실시간 탐지하고 차단합니다.
   - 공식 **OWASP CRS (Core Rule Set)** 및 Aegis-3 전용 커스텀 정책 룰셋을 원격 통합 관리합니다.

2. **개인정보 자동 마스킹 (Nginx Sub Filter)**
   - 백엔드 응답 본문 내에 노출된 전화번호(`010-XXXX-XXXX`), 주민등록번호 등 민감 정보를 Nginx의 `sub_filter` 모듈로 가로채 `010-9999-****` 등의 안전한 마스크 형태로 실시간 치환하여 개인정보 유출을 원천 봉쇄합니다.

3. **Express 동적 보안 라우팅 프록시 (Aegis-3 Proxy)**
   - PostgreSQL 데이터베이스에 등재된 멀티테넌트(Tenant) 및 동적 라우팅 정책을 기반으로 라우팅 처리를 수행합니다.
   - `/api/v1/*` 정상 경로 프록시 매칭은 물론, `/.env`와 같은 환경변수 탈취 공격은 **허니팟(Honeypot Decoy)** 으로 매핑하여 공격자를 안심시키고 백그라운드로 보안 침입 이벤트를 캡처합니다.

4. **SOAR 비동기 분산 수집기 (Redis + Celery Worker + Beat)**
   - 침입 Proxy가 캡처한 위협 이벤트를 `Redis` 분산 대기열 큐에 안전하게 완충합니다.
   - `Celery Worker` 백그라운드 데몬이 이벤트 데이터를 파싱, 정규화 및 정밀 검증합니다.
   - **Celery Beat** 가 워커에 내장되어 2초 주기로 큐를 자동 소비하므로, 별도 트리거 없이 들어오는 이벤트가 즉시 분석 파이프라인을 타고 흐릅니다 (`BEAT_CONSUME_INTERVAL` 환경변수로 주기 조정 가능).

5. **Risk Score Engine 정량 분석 (`soar/risk_score_engine`)**
   - 워커가 정규화한 이벤트를 Flask 기반 `detection-engine` 서비스의 `/analyze` 엔드포인트로 전달합니다.
   - 민감 경로 접근, Payload 우회, SSRF, Command Injection 등 다중 detector 가 점수를 합산하여 `risk_score` (0~100), `level` (LOW/SUSPICIOUS/HIGH/CRITICAL), `rule_hits`, `reasons` 가 포함된 정량 결과를 반환합니다.
   - 결과는 MongoDB `aegis_logs.security_logs` 컬렉션에 모든 상세 정보와 함께 영구 저장됩니다.

6. **AI 자동 WAF 룰 생성기 (Gemini LLM + 사이드카 주입)**
   - `risk_score ≥ AI_RULE_THRESHOLD` (기본 80) 인 고위험 이벤트가 발생하면, `ai_engine.py` 가 **Google Gemini 2.5 Flash** 를 호출하여 공격 로그를 분석하고 차단용 **PCRE 정규식 + Coraza SecRule** 을 자동 생성합니다.
   - **JSON 강제 출력 모드**, **3회 피드백 루프**, **`re.compile` 사전 검증** 으로 잘못된 정규식이 적용되지 않게 방어합니다.
   - 생성된 룰은 **Nginx 컨테이너 내부 Node.js 사이드카(:4000)** 의 `/api/v1/rules/inject` 로 전송되어 `/etc/nginx/rules/dynamic.conf` 에 append 되고 `nginx -s reload` 가 자동 실행되어 **즉시 차단** 에 반영됩니다.
   - AI 룰 ID 는 OWASP CRS (9xxxxxx) 와 격리된 **2,000,000,000~2,099,999,999** 범위를 ms 정밀도로 채워 자체 충돌도 회피합니다.
   - `dynamic.conf` 는 named volume(`nginx_dynamic_rules`)으로 마운트되어 컨테이너 재시작에도 학습된 룰이 보존됩니다.

7. **실시간 관제 및 긴급 오케스트레이션 (Analyzer)**
   - **Cloudflare WAF 연동:** 공격 IP에 대한 Cloudflare 방화벽 차단 API를 호출하여 해당 IP를 네트워크 엣지 단에서 영구 격리합니다.
   - **Slack 연동:** Slack Bolt 소켓 기반의 실시간 경보 메시지를 `#security-alerts` 관제 채널에 포맷팅하여 전송합니다.
   - **Email 연동:** SMTP 프로토콜을 통하여 관제 담당자의 편지함에 직관적이고 미려한 HTML 위협 분석 보고서를 발송합니다.

8. **고객사 대시보드 백엔드 (Aegis Portal Backend, FastAPI)**
   - MongoDB(트래픽 로그)와 PostgreSQL(고객사/라우팅 정보)을 함께 조회하여 대시보드용 로그 목록·통계·실시간(SSE) 스트림 API를 제공합니다.
   - **Supabase JWT 인증:** 모든 `/api/*` 요청을 Supabase JWKS(공개키)로 서명 검증하고, `user_profiles` 테이블에서 role 을 조회(5분 캐시)하여 권한을 판별합니다.
   - **멀티테넌트 격리:** `admin` 은 전체 데이터, `customer` 는 본인 소유 `tenant_id` 로만 자동 필터링되어 타 고객사 로그 접근을 차단합니다.
   - **고객사 등록:** `POST /api/customers` 로 tenants/routers 테이블에 등록하며 `api_key` 를 자동 생성합니다.

---

## 📂 디렉터리 구조

```text
Aegis-3/
├── docker-compose.yml              # 전체 통합 다중 컨테이너 오케스트레이션 설정
├── .env                            # MongoDB/PostgreSQL/Gemini 마스터 자격증명
├── data/
│   └── init.sql                    # PostgreSQL 테넌트 및 라우팅/허니팟 초기 데이터
├── nginx/
│   ├── Dockerfile                  # libcoraza & coraza-nginx 컴파일 + Node.js + 사이드카 빌드
│   ├── entrypoint.sh               # nginx + 사이드카 동시 기동, dynamic.conf 보장
│   ├── sidecar.js                  # Express :4000, /api/v1/rules/inject, nginx -s reload
│   ├── package.json                # 사이드카 Node 의존성 (express)
│   ├── nginx.conf                  # Nginx 코어 설정 (Coraza 모듈 로드, 마스킹, 프록시)
│   ├── coraza.conf                 # Coraza WAF 엔진 설정 (CRS + custom + dynamic.conf Include)
│   ├── crs-setup.conf              # OWASP CRS 메인 기동 구성 파일
│   ├── crs/                        # OWASP CRS 보안 룰셋 디렉터리 (setup-crs.sh로 구성)
│   └── rules/
│       ├── aegis3-custom-rules.conf # Aegis-3 전용 정적 차단 룰
│       └── dynamic.conf            # AI 가 런타임에 적재하는 SecRule (named volume 영속)
├── proxy/
│   ├── app.js                      # Express 동적 라우터, Redis 큐 연동 보안 프록시 본체
│   └── db.js                       # PostgreSQL DB Connection Pool 관리자
├── soar/
│   └── risk_score_engine/          # Flask Risk Score 정량 분석기 (detection-engine 서비스)
│       ├── Dockerfile
│       ├── app.py                  # /analyze 엔드포인트, detector 합산, alert event 생성
│       ├── config.py               # ALERT_THRESHOLD, 민감 경로/우회/SSRF/RCE 패턴 정의
│       ├── detectors.py            # 다중 detector 함수 (점수 + rule_hits + reasons)
│       ├── state.py                # IP/세션별 시간 윈도우 상태 관리
│       └── utils.py                # 시간 파싱, level 계산
└── services/
    └── ingestion/
        ├── celery_app/             # Celery SOAR 워커 및 인제스션 API (FastAPI)
        │   ├── Dockerfile
        │   ├── main.py             # /webhook/logs, /tasks/consume, /health
        │   ├── celery_app.py       # Celery 앱 + Beat 스케줄 (2초 주기 자동 소비)
        │   ├── tasks.py            # process_security_log: Risk→Mongo→AI→사이드카 주입
        │   ├── ai_engine.py        # Gemini 2.5 Flash 호출 + JSON 강제 + 피드백 루프
        │   └── requirements.txt
        ├── analyzer/               # Node.js 기반 실시간 알림/차단 자동 대응 엔진
        │   ├── Dockerfile
        │   ├── analyzer.js         # 슬랙, 이메일(SMTP), Cloudflare API 처리 엔진 본체
        │   ├── .env                # 이메일/슬랙/Cloudflare 연동용 자격증명 저장소
        │   └── package.json
        └── aegis-portal-backend/   # 고객사 대시보드 로그/통계 조회 API (FastAPI, :8001)
            ├── Dockerfile
            ├── requirements.txt
            ├── .env.example        # 로컬 테스트용 환경변수 템플릿 (.env 는 커밋 금지)
            └── app/
                ├── main.py         # FastAPI 엔드포인트 (로그/통계/SSE/고객사)
                ├── auth.py         # Supabase JWT 검증 + role(user_profiles) 판별
                ├── customers.py    # 고객사(tenant) 등록·조회, 소유 tenant_id 필터
                ├── database.py     # MongoDB 연결 (트래픽 로그)
                ├── postgres.py     # PostgreSQL 연결 (고객사/라우팅 정보)
                ├── seed_data.py    # [길1 전용] 더미 로그 생성기 (운영 시 삭제)
                └── stream_source.py # SSE 스트림 소스 (dummy → change_stream 전환)
```

---

## 🚀 시작하기 (가동 순서)

### 1. OWASP CRS 룰셋 셋업 (최초 1회 필수)
프로젝트 처음 내려받은 후, 공식 OWASP Core Rule Set 룰 패키지들을 `nginx/crs/` 하위로 다운로드하기 위해 스크립트를 기동합니다.
```bash
./scripts/setup-crs.sh
```

### 2. 환경 변수 구성
* **Aegis 인프라 자격증명 + AI 키 설정 (`./.env`):**
  ```env
  # 인프라 패스워드
  MONGO_PASSWORD=your_secure_password
  POSTGRES_PASSWORD=your_secure_password

  # AI WAF 룰 생성기 (Google Gemini)
  GEMINI_API_KEY=your_gemini_api_key

  # 선택: AI 룰 생성 임계점수 (risk_score ≥ 이 값 → AI 호출). 기본 80.
  AI_RULE_THRESHOLD=80

  # 선택: 사이드카 룰 주입 엔드포인트. 기본 http://nginx:4000/api/v1/rules/inject
  NGINX_SIDECAR_URL=http://nginx:4000/api/v1/rules/inject

  # 선택: Celery Beat 가 Redis 큐를 폴링하는 주기(초). 기본 2.0
  BEAT_CONSUME_INTERVAL=2.0
  ```
  > **Note:** MongoDB 패스워드에 `@ : / ? #` 같은 RFC 3986 reserved 문자가 들어가도 워커가 자동으로 URL-encode 합니다 (`MONGO_USER`, `MONGO_HOST`, `MONGO_PORT`, `MONGO_AUTH_SOURCE` 별도 env 로 받아 안전하게 URI 조립).

* **대응 엔진 자격증명 설정 (`./services/ingestion/analyzer/.env`):**
  ```env
  CF_TOKEN=your_cloudflare_api_token
  ZONE_ID=your_cloudflare_zone_id
  SLACK_BOT_TOKEN=xoxb-your-slack-bot-token
  SLACK_SIGNING_SECRET=your-slack-signing-secret
  EMAIL_USER=your-smtp-sender@gmail.com
  EMAIL_PASS=your-smtp-16-digit-app-password
  ```
  > **Tip (Gmail SMTP):** 구글 메일 연동 시, 2단계 인증을 활성화한 후 구글 계정 보안 페이지에서 생성한 **공백(띄어쓰기)이 완전히 제거된 16자리 앱 비밀번호**를 기입해야 구글 서버 인증에 성공합니다.

* **대시보드 백엔드 Supabase 인증 (`./.env` — portal-backend 가 컨테이너 environment 로 주입받음):**
  ```env
  # Supabase 프로젝트 URL (JWKS 공개키 + REST API 공통)
  SUPABASE_URL=https://<프로젝트_ref>.supabase.co

  # user_profiles 조회용 Service Role Key (RLS 우회, 절대 외부 노출 금지)
  SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key

  # 선택: 토큰 aud 값. 기본 authenticated (보통 변경 불필요)
  # SUPABASE_JWT_AUDIENCE=authenticated
  ```
  > **Note:** 로컬 테스트는 `services/aegis-portal-backend/.env.example` 을 복사해 `.env` 로 채우면 됩니다.
  > 운영(EC2)에서는 `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` 를 **GitHub Secrets** 에 등록하면 `deploy.yml` 이 `.env` 로 생성하고 docker-compose 가 portal-backend 컨테이너에 주입합니다.
  > `SUPABASE_JWT_AUDIENCE` 는 비밀이 아니므로 Secrets 에 넣지 않으며, 미설정 시 compose 기본값 `authenticated` 가 사용됩니다.

### 3. 전체 시스템 빌드 및 컨테이너 가동
```bash
docker compose up -d --build
```
모든 다중 서비스들(nginx + 사이드카, proxy, postgres, redis, mongodb, soar-api, soar-worker + Beat, detection-engine, analyzer, portal-backend)이 Docker 가상 컴퓨터 위에서 부팅되어 완벽한 고립 네트워크 상태로 작동됩니다.

> **첫 빌드 시간:** libcoraza + coraza-nginx 모듈 컴파일 때문에 5~10분이 걸릴 수 있습니다. 

### 4. End-to-End 동작 확인 (선택)
```bash
# Coraza 자체 차단 (CRS 또는 custom 룰)
curl -i "http://localhost:8080/?aegis_test=1"          # → HTTP 403 (test rule id:100)

# 사이드카 헬스
docker exec aegis-nginx wget -qO- http://localhost:4000/health  # → {"ok":true,...}

# Beat 스케줄러 가동 로그
docker logs aegis-soar-worker | grep "Sending due task consume-redis-queue"

# 고위험 이벤트 직접 주입 → AI 룰 생성 → 적용까지 한 번에
docker exec aegis-redis redis-cli LPUSH aegis:security-events \
  '{"event_id":"demo","ip":"1.2.3.4","path":"/admin/login","method":"POST",
    "query":"id=1 UNION SELECT pw","headers":{"user-agent":"sqlmap"},"analysis_profile":"full"}'

docker exec aegis-nginx cat /etc/nginx/rules/dynamic.conf   # AI 가 만든 SecRule 확인
```

---

## > 운영 배포 시 정리 항목 (Production cleanup)

테스트/디버그용 코드는 **로컬 개발 편의를 위해 리포지토리에 그대로 둡니다.**
운영(EC2 prod) 배포 시에는 아래 두 가지 방식으로 분리해서 처리합니다.

### A. 자동 처리 — `.dockerignore` 가 컨테이너 빌드에서 자동 제외

다음 파일들은 각 서비스 폴더의 `.dockerignore` 로 처리되어 운영 이미지에 들어가지 않습니다.
**별도 작업 불필요**, `docker compose up -d --build` 만으로 자동 적용됩니다.

| 파일 | 제외 정의 | 이유 |
|---|---|---|
| `services/ingestion/celery_app/test_waf.py` | `celery_app/.dockerignore` (`test_*.py`) | 수동 WAF 페이로드 테스트 스크립트 (SQLi/XSS 페이로드를 Celery에 직접 LPUSH) |
| `services/aegis-portal-backend/venv/`, `.env`, `__pycache__/` | `aegis-portal-backend/.dockerignore` | 로컬 virtualenv, 자격증명, Python 캐시 |
| `services/ingestion/celery_app/__pycache__/`, `*.pyc`, `.env` | `celery_app/.dockerignore` | 동일 |

> `.env` 는 deploy.yml 이 GitHub Secrets → 컨테이너 environment 로 별도 주입하므로 운영 이미지에 들어갈 필요가 없습니다.

### B. 수동 처리 — 운영 전환 시 코드/데이터 직접 편집

다음 항목들은 다른 코드가 `import` 하거나 인라인으로 작성돼 있어서
`.dockerignore` 로 제외할 수 없습니다. **코드 자체를 손봐야 합니다.**

| 파일 | 처리 내용 |
|---|---|
| [services/aegis-portal-backend/app/seed_data.py](services/aegis-portal-backend/app/seed_data.py) | 파일 삭제 (더미 로그 생성기) |
| [services/aegis-portal-backend/app/main.py](services/aegis-portal-backend/app/main.py) | `from .seed_data import generate_logs` import 제거 + `POST /api/seed` 엔드포인트 블록 (현재 84~93줄) 삭제 + docstring의 "길1 전용" 줄 정리 |
| [services/aegis-portal-backend/app/stream_source.py](services/aegis-portal-backend/app/stream_source.py) | 맨 아래 `event_stream = dummy_stream` → `event_stream = change_stream` 으로 변경. **단, MongoDB가 replica set 모드여야 동작** ([docker-compose.yml](docker-compose.yml) 의 mongodb 서비스에 `command: ["--replSet","rs0"]` 추가 + 최초 1회 `rs.initiate()` 필요) |
| [proxy/app.js](proxy/app.js) | 13~27줄의 데모 핸들러 (`/` 배너 응답, `/user` 마스킹 테스트 JSON) 삭제 |
| [data/init.sql](data/init.sql) | `Test Company` 및 `localhost` 테스트 라우트 INSERT 블록 삭제 — 실 고객사는 portal-backend의 `POST /api/customers` 로 등록 |

### C. 이미 EC2에 떠있는 컨테이너 즉시 정리 명령어

`.dockerignore` 변경이 main 에 머지된 후 다음 자동 배포(deploy.yml) 때 자동으로 정리되지만,
**바로** 정리하고 싶다면 EC2 에서:

```bash
# 1) [임시] 떠있는 컨테이너 안의 test_waf.py 즉시 삭제
sudo docker exec aegis-soar-api    rm -f /app/test_waf.py
sudo docker exec aegis-soar-worker rm -f /app/test_waf.py

# 2) [영구] 새 .dockerignore 가 적용된 이미지로 재빌드
cd /home/ubuntu/Aegis-3
git pull origin main
sudo docker compose up -d --build soar-api soar-worker portal-backend

# 3) [선택] B 항목까지 모두 적용한 상태에서 재빌드하려면
#    먼저 위 B 표대로 코드를 수정해 커밋한 뒤 git pull → 같은 명령으로 재빌드
sudo docker compose up -d --build portal-backend proxy nginx
```

### 정리 체크리스트

운영 첫 배포 직전에 한 번 확인:

- [ ] `services/*/test_*.py`, `*_test.py` 가 컨테이너에 들어가지 않는지 확인:
      `docker exec aegis-soar-api ls /app/ | grep -i test` → 결과 없어야 함
- [ ] portal-backend `/api/seed` 호출 시 404 인지 확인 (B 항목 적용됨)
- [ ] 대시보드에 더미 로그가 아닌 실 SOAR 파이프라인 로그가 흐르는지 확인 (`stream_source.py` 가 change_stream 로 전환됨)
- [ ] `data/init.sql` 의 `Test Company` 가 운영 DB 에 없는지 확인:
      `docker exec aegis-postgres psql -U aegis_admin -d aegis_proxy -c "SELECT company_name FROM tenants"`
- [ ] 노출된 자격증명이 GitHub Secrets / EC2 .env / DB 비밀번호 어디에도 남아있지 않은지 확인