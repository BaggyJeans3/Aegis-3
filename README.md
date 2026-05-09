# 🛡️ Aegis-3: Intelligent API Security Gateway

**Aegis-3**는 Nginx + Coraza WAF를 앞단 보안 게이트웨이로 두고, 내부 Express.js 프록시가 테넌트별 라우팅·허니팟·차단 정책을 처리하는 졸업작품용 API 보안 시스템입니다.

## 핵심 구조

1. **Nginx + Coraza WAF**
   - SQL Injection, XSS, 민감 파일 접근 등 기본 웹 공격 차단
   - 차단 시 `403 Forbidden` 반환

2. **Express Proxy**
   - PostgreSQL의 라우팅 정책을 캐싱
   - 정상 API는 백엔드로 프록시
   - 허니팟 경로 접근 시 보안 이벤트 기록
   - 정책상 차단 경로는 즉시 차단

3. **PostgreSQL / Redis / MongoDB**
   - PostgreSQL: 테넌트 및 라우팅 정책 저장
   - Redis: 실시간 보안 이벤트 큐
   - MongoDB: 추후 로그 저장/분석 확장용

## 실행

```bash
sudo docker compose up -d --build
```

## 상태 확인

```bash
curl http://localhost/
curl http://localhost/health
```

## Coraza WAF 연동 확인

아래 요청이 `403`이면 Coraza WAF가 정상 동작하는 것입니다.

```bash
curl -i "http://localhost/?aegis_test=1"
```

SQL Injection 테스트:

```bash
curl -i "http://localhost/user?id=1%20OR%201=1"
```

XSS 테스트:

```bash
curl -i "http://localhost/user?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

민감 파일 접근 테스트:

```bash
curl -i "http://localhost/.env"
```

## 개인정보 마스킹 확인

```bash
curl http://localhost/user
```

응답의 전화번호와 주민번호 일부가 `****`로 치환되면 Nginx 응답 마스킹도 정상 동작한 것입니다.

## 주의

- `nginx/Dockerfile`은 Coraza Nginx Connector와 libcoraza를 빌드합니다. 최초 빌드는 시간이 걸릴 수 있습니다.
- Coraza Nginx Connector는 공식적으로 Nginx 연결용 모듈이지만, 저장소 설명상 experimental connector입니다. 졸작 데모에는 충분하지만 운영 환경이라면 Caddy/Envoy/Proxy-Wasm 방식도 비교 검토하는 것이 좋습니다.
- 현재 룰은 데모용 최소 룰입니다. 최종 발표용으로는 OWASP Core Rule Set 연동 또는 커스텀 룰 확장이 필요합니다.
