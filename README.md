# 🛡️ Aegis-3: Intelligent API Security Gateway & SOAR Orchestrator

**Aegis-3**는 **Nginx + Coraza WAF** 모듈식 방화벽 레이어와 **Express.js 지능형 프록시**, 그리고 **Celery 기반 SOAR 파이프라인(Queue-Worker)** 과 **실시간 위협 대응 엔진(Analyzer)** 을 결합한 통합 지능형 API 보안 게이트웨이 및 자동 대응 플랫폼입니다. 

외부 침입 탐지 및 차단은 물론, 민감 정보 자동 마스킹, 내부 유입 로그의 분산 비동기 전처리, 그리고 API를 통한 **Slack 알림, Cloudflare IP 영구 차단, 긴급 이메일 전송**까지 일관된 오케스트레이션을 제공합니다.

---

## > 현재 시스템 아키텍처 및 데이터 흐름(진행중)

```text
  [공격자/사용자 요청]
          │
          ▼
┌─────────────────────────────────┐
│        Nginx Web Server         │ (Port 80)
│  ├─ ngx_http_coraza_module      │ (실시간 WAF 검사 / CRS 차단)
│  └─ ngx_http_sub_module         │ (전화번호/주민번호 정규식 마스킹)
└────────────────┬────────────────┘
                 │ (Proxy Pass)
                 ▼
┌─────────────────────────────────┐
│        Aegis-3 Proxy            │ (Port 3000)
│  ├─ Express Dynamic Router      │ (DB 라우팅 매칭)
│  └─ honeypot / block / decoy    │ (허니팟 유인 / 403 차단)
└────────────────┬────────────────┘
                 │ (Event Push)
                 ▼
┌─────────────────────────────────┐
│          Redis Queue            │ (aegis:security-events 리스트)
└────────────────┬────────────────┘
                 │ (Periodic RPOP / delay())
                 ▼
┌─────────────────────────────────┐
│    Celery Background Worker     │ (SOAR 비동기 로그 수집 및 전처리)
└────────────────┬────────────────┘
                 │ (Threat Report HTTP POST)
                 ▼
┌─────────────────────────────────┐
│       Aegis-3 Analyzer          │ (Port 5000 / Node.js 위협 대응 엔진)
│  ├─ Cloudflare WAF Block API    │ (공격 IP 방화벽 영구 차단)
│  ├─ Slack Bolt App              │ (#security-alerts 채널 실시간 경보)
│  └─ nodemailer (SMTP)           │ (관리자 대상 긴급 메일 보고서 전송)
└─────────────────────────────────┘
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

4. **SOAR 비동기 분산 수집기 (Redis + Celery Worker)**
   - 침입 Proxy가 캡처한 위협 이벤트를 `Redis` 분산 대기열 큐에 안전하게 완충합니다.
   - `Celery Worker` 백그라운드 데몬이 이벤트 데이터를 파싱, 정규화 및 정밀 검증하여 자동 차단 필요 여부를 판별하고 보안 경보 메시지를 생성합니다.

5. **실시간 관제 및 긴급 오케스트레이션 (Analyzer)**
   - **Cloudflare WAF 연동:** 공격 IP에 대한 Cloudflare 방화벽 차단 API를 호출하여 해당 IP를 네트워크 엣지 단에서 영구 격리합니다.
   - **Slack 연동:** Slack Bolt 소켓 기반의 실시간 경보 메시지를 `#security-alerts` 관제 채널에 포맷팅하여 전송합니다.
   - **Email 연동:** SMTP 프로토콜을 통하여 관제 담당자의 편지함에 직관적이고 미려한 HTML 위협 분석 보고서를 발송합니다.

---

## 📂 디렉터리 구조

```text
Aegis-3/
├── docker-compose.yml              # 전체 통합 다중 컨테이너 오케스트레이션 설정
├── .env                            # MongoDB/PostgreSQL 마스터 패스워드 설정
├── data/
│   └── init.sql                    # PostgreSQL 테넌트 및 라우팅/허니팟 초기 데이터
├── nginx/
│   ├── Dockerfile                  # libcoraza & coraza-nginx 모듈 컴파일 및 Nginx 빌드
│   ├── nginx.conf                  # Nginx 코어 설정 (프록시 및 응답 마스킹 규칙 정의)
│   ├── coraza.conf                 # Coraza WAF 코어 엔진 엔진 설정 (Audit Log 정의)
│   ├── crs-setup.conf              # OWASP CRS 메인 기동 구성 파일
│   ├── crs/                        # OWASP CRS 보안 룰셋 디렉터리 (setup-crs.sh로 구성)
│   └── rules/
│       └── aegis3-custom-rules.conf # Aegis-3 전용 자체 차단 규칙 룰셋
├── proxy/
│   ├── app.js                      # Express 동적 라우터, Redis 큐 연동 보안 프록시 본체
│   └── db.js                       # PostgreSQL DB Connection Pool 관리자
└── services/
    └── ingestion/
        ├── celery_app/             # Celery SOAR 워커 및 인제스션 API (FastAPI) 디렉터리
        │   ├── Dockerfile
        │   ├── main.py             # 수집 수동 트리거 API 및 웹훅 엔드포인트
        │   ├── celery_app.py       # Celery 앱 기동 및 Redis 클라이언트 초기화
        │   ├── tasks.py            # 로그 파싱, 침입 감지, Analyzer 연동 조치 비동기 태스크
        │   └── requirements.txt
        └── analyzer/               # Node.js 기반 실시간 알림/차단 자동 대응 엔진
            ├── Dockerfile
            ├── analyzer.js         # 슬랙, 이메일(SMTP), Cloudflare API 처리 엔진 본체
            ├── .env                # 이메일/슬랙/Cloudflare 연동용 자격증명 저장소
            └── package.json
```

---

## 🚀 시작하기 (가동 순서)

### 1. OWASP CRS 룰셋 셋업 (최초 1회 필수)
프로젝트 처음 내려받은 후, 공식 OWASP Core Rule Set 룰 패키지들을 `nginx/crs/` 하위로 다운로드하기 위해 스크립트를 기동합니다.
```bash
./scripts/setup-crs.sh
```

### 2. 환경 변수 구성
* **Aegis 인프라 마스터 패스워드 설정 (`./.env`):**
  ```env
  MONGO_PASSWORD=your_secure_password
  POSTGRES_PASSWORD=your_secure_password
  ```

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

### 3. 전체 시스템 빌드 및 컨테이너 가동
```bash
docker-compose up -d --build
```
모든 다중 서비스들이 Docker 가상 컴퓨터 위에서 부팅되어 완벽한 고립 네트워크 상태로 작동됩니다.