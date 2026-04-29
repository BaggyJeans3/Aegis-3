# 🛡️ Aegis-3: Intelligent API Security Gateway

**Aegis-3**는 Nginx와 Coraza WAF를 결합하여 외부 공격을 차단하고, 내부의 민감한 개인정보를 자동으로 마스킹하는 지능형 보안 게이트웨이입니다.

## ✨ 주요 기능

- **WAF 방어:** SQL Injection 및 XSS 공격 실시간 탐지 및 차단 (403 Forbidden).
- **개인정보 마스킹:** 응답 데이터 내의 전화번호, 주민번호 등 민감 정보를 `****`로 자동 치환.
- **도커 기반 인프라:** Express, PostgreSQL, Redis를 컨테이너화하여 안정적인 백엔드 환경 구축.

## 🏗️ 시스템 아키텍처

- **WAF Layer:** Nginx + Coraza WAF (Host Side)
- **Application Layer:** Express.js Proxy (Docker Container)
- **Data Layer:** PostgreSQL & Redis (Docker Container)

## 🚀 시작하기

1. 본체 가동: `sudo docker compose up -d --build`
2. 방패 가동: `sudo LD_LIBRARY_PATH=/usr/local/lib /usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf`

## 🛠️ 기술 스택

- **Language:** Node.js (Express)
- **Security:** Coraza WAF, Nginx (Source Build)
- **Database:** PostgreSQL, Redis
- **Infra:** Docker, WSL2 (Ubuntu 24.04)
