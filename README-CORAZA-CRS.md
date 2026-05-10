# Aegis-3 Coraza + OWASP CRS 적용 구조

이 프로젝트는 Coraza WAF가 Nginx 모듈로 동작한다.
따라서 Coraza 관련 파일은 최상위 `coraza/` 폴더를 만들지 않고, 기존 `nginx/` 폴더 안에서 관리한다.

## 최종 구조

```text
Aegis-3-proto/
├── docker-compose.yml
├── nginx/
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── coraza.conf
│   ├── crs-setup.conf
│   ├── crs/
│   │   ├── rules/
│   │   └── 기타 CRS 파일들
│   └── rules/
│       └── aegis3-custom-rules.conf
├── proxy/
├── data/
└── infra/
```

## 적용 방식

`nginx/nginx.conf`는 다음 파일을 Coraza 진입점으로 읽는다.

```nginx
coraza_rules_file /etc/nginx/coraza.conf;
```

따라서 `nginx/coraza.conf`에서 OWASP CRS와 Aegis-3 커스텀 룰을 Include한다.

```apache
Include /etc/nginx/crs-setup.conf
Include /etc/nginx/crs/rules/*.conf
Include /etc/nginx/rules/aegis3-custom-rules.conf
```

## CRS 다운로드

처음 받은 ZIP에는 CRS 전체 파일이 들어있지 않다. 아래 명령으로 공식 OWASP CRS를 설치한다.

```bash
./scripts/setup-crs.sh
```

그 다음 컨테이너를 재빌드한다.

```bash
docker compose down
docker compose up -d --build
```

## 테스트

```bash
curl -i "http://localhost/?aegis_test=1"
curl -i "http://localhost/api/v1/admin"
curl -i "http://localhost/.env"
```

정상 동작 시 403 응답이 나온다.
