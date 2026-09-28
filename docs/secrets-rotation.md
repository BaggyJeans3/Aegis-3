# Aegis-3 시크릿 로테이션 주기표

모든 값은 GitHub Secrets(`Settings → Secrets and variables → Actions`)에 저장되고,
[.github/workflows/deploy.yml](../.github/workflows/deploy.yml)이 배포 시 EC2의 `.env`
(루트 / `services/ingestion/analyzer/.env`)로 주입한다. 로컬 개발은 각자 `.env`에 값을 채워 사용.

## 로테이션 대상

| 시크릿 | 용도 | 사용처 | 권장 주기 | 비고 |
| --- | --- | --- | --- | --- |
| `EC2_SSH_KEY` | 배포 시 EC2 SSH 접속 | deploy.yml | **90일** | 서버 직접 접근 키 — 최우선 |
| `POSTGRES_PASSWORD` | PostgreSQL(tenants/routers) 접속 | proxy, portal-backend | 90일 | |
| `MONGO_PASSWORD` | MongoDB(로그) 접속 | soar-worker, portal-backend | 90일 | |
| `SUPABASE_SERVICE_ROLE_KEY` | RLS 우회, 회원 조회 | portal-backend (auth.py) | 90일 | 유출 시 전체 회원 데이터 노출 — 고위험 |
| `ADMIN_REFRESH_KEY` | `/admin/routes/refresh` 인증 | proxy | 90일 | |
| `TS_OAUTH_CLIENT_ID` / `TS_OAUTH_SECRET` | GitHub Actions → Tailscale 네트워크 접속 | deploy.yml | 180일 | |
| `GEMINI_API_KEY` | AI 룰 생성기(Gemini) | ai_engine | 180일 | 과금 연동 — 유출 시 비용 발생 |
| `CF_TOKEN` | Cloudflare WAF 차단/해제 API | analyzer | 180일 | |
| `SLACK_BOT_TOKEN` | Slack ChatOps 봇 | analyzer | 180일 | ⚠️ invalid_auth로 무효 — 즉시 재발급 필요 |
| `SLACK_SIGNING_SECRET` | Slack 요청 서명 검증 | analyzer | 180일 | 봇 토큰 재발급 시 같이 확인 |
| `SLACK_APP_TOKEN` | Slack Socket Mode 연결 | analyzer | 180일 | 봇 토큰 재발급 시 같이 확인 |
| `EMAIL_PASS` | SMTP 발송 계정 앱 비밀번호 | analyzer | 180일 | |

## 로테이션 불필요 (시크릿 아님 — 식별자/URL)

| 값 | 비고 |
| --- | --- |
| `EC2_TAILSCALE_IP` | 인프라 변경 시에만 갱신 |
| `ZONE_ID` (Cloudflare) | Cloudflare 존 변경 시에만 |
| `SUPABASE_URL` | 프로젝트 재생성 시에만 |
| `EMAIL_USER` | 계정 자체가 아니라 식별자 |

## 유령 키

코드 전체에서 사용처가 없는 시크릿은 `deploy.yml`에서 제거했다. **GitHub Secrets 저장소에서도
직접 삭제 필요** — 코드에서 안 쓴다고 자동으로 없어지지 않는다.

- `SLACK_WEBHOOK_URL` — 루트/analyzer `.env` 양쪽에 주입되고 있었으나 미사용
- `OPENAI_API_KEY` — analyzer `.env`에 주입되고 있었으나 미사용

반대로 `ADMIN_REFRESH_KEY`는 [proxy/app.js](../proxy/app.js)가 요구하는데 어디에도 배선돼
있지 않아 `/admin/routes/refresh`가 항상 401만 반환하던 상태였다 — `docker-compose.yml` +
`deploy.yml`에 정식 배선함.

## 새 시크릿 추가 시 체크리스트

1. GitHub Secrets에 값 등록
2. `deploy.yml`의 해당 `.env` 생성 블록에 라인 추가
3. 실제로 그 값을 읽는 코드가 있는지 확인 (`grep -rn VAR_NAME` — 없으면 애초에 추가하지 말 것)
4. 이 표에 용도/사용처/권장 주기 추가
