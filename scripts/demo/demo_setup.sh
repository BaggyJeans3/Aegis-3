#!/bin/bash
# ============================================================
# Aegis-3 시연 환경 사전 준비 스크립트
# 사용법: ./demo_setup.sh
#
# [중요] 운영 안전값 위에서 시연용 튜닝을 "런타임으로만" 적용한다.
#   - 커밋된 설정(main)은 운영 안전값 유지 (AI threshold 80, Coraza 풀룰, rate limit on)
#   - 이 스크립트가 시연 동안만 약화: AI threshold 30 + Coraza 930130/130010 제거
#   - 시연 후 demo_restore.sh 가 git checkout 으로 전부 원복
# ============================================================

# 리포지토리 루트 (이 스크립트는 scripts/demo/ 안에 있음)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE="-f $REPO_ROOT/docker-compose.yml -f $REPO_ROOT/docker-compose.prod.yml"

echo "════════════════════════════════════════"
echo "  Aegis-3 시연 환경 준비 시작"
echo "════════════════════════════════════════"
echo "  리포지토리: $REPO_ROOT"
echo ""

# 1. 시연용 런타임 튜닝 적용 (운영 안전값 → 시연값, 임시)
echo "▸ 1. 시연용 런타임 튜닝 적용"

# 1-a. AI 룰 생성 임계값 80 → 30 (시연 이벤트는 40점이라 80이면 룰이 안 생김)
echo "  ▹ soar-worker AI_RULE_THRESHOLD=30 으로 재기동..."
( cd "$REPO_ROOT" && sudo env AI_RULE_THRESHOLD=30 docker compose $COMPOSE up -d --force-recreate --no-deps soar-worker ) \
  && echo "    ✓ soar-worker 재기동 (threshold=30)" \
  || echo "    ⚠ soar-worker 재기동 실패"

# 1-b. Coraza 민감파일 차단룰(930130/130010) 임시 제거 → /.env 허니팟 유인 동작
CORAZA_HOST="$REPO_ROOT/nginx/coraza.conf"
if ! grep -q "SecRuleRemoveById 930130" "$CORAZA_HOST" 2>/dev/null; then
  cat >> "$CORAZA_HOST" <<'EOF'

# [시연 임시 - demo_setup.sh 자동 추가] 허니팟 유인: 민감파일 접근을 허니팟으로.
# demo_restore.sh 의 git checkout 으로 원복됨. 커밋하지 말 것.
SecRuleRemoveById 930130
SecRuleRemoveById 130010
EOF
  echo "  ▹ Coraza 930130/130010 임시 제거 (허니팟 유인용)"
else
  echo "  ▹ Coraza 임시 제거 룰 이미 적용됨 (무시)"
fi
sudo docker exec aegis-nginx nginx -s reload 2>/dev/null \
  && echo "    ✓ nginx reload 완료" \
  || echo "    ⚠ nginx reload 실패 (nginx 미기동?)"

echo ""
echo "  (참고: nginx 의 SHADOW_DURATION/TTL_SECONDS 시연값은 docker-compose.yml 의"
echo "   nginx 서비스 environment 에 이미 반영되어 있음)"
echo ""
sleep 3

# 2. audit 로그 초기화
echo "▸ 2. Coraza audit 로그 초기화"
sudo docker exec aegis-nginx truncate -s 0 /var/log/coraza/audit.log 2>/dev/null && \
  echo "  ✓ audit.log 초기화 완료" || \
  echo "  ⚠ audit.log 초기화 실패 (nginx 미기동?)"
echo ""

# 3. Redis 큐 비우기 (이전 이벤트 영향 차단)
echo "▸ 3. Redis 큐 및 통계 초기화"
sudo docker exec aegis-redis redis-cli DEL aegis:security-events > /dev/null
sudo docker exec aegis-redis redis-cli KEYS "aegis:blacklist:*" | xargs -r sudo docker exec -i aegis-redis redis-cli DEL > /dev/null 2>&1
sudo docker exec aegis-redis redis-cli KEYS "aegis:cluster:*" | xargs -r sudo docker exec -i aegis-redis redis-cli DEL > /dev/null 2>&1
echo "  ✓ Redis 큐·블랙리스트·클러스터 캐시 초기화"
echo ""

# 4. AI 룰 초기화 (시연용 fresh start)
echo "▸ 4. AI 동적 룰 초기화"
sudo docker exec aegis-nginx truncate -s 0 /etc/nginx/rules/dynamic.conf 2>/dev/null && \
  echo "  ✓ dynamic.conf 초기화 완료" && \
  sudo docker exec aegis-nginx nginx -s reload 2>/dev/null && \
  echo "  ✓ nginx reload 완료" || \
  echo "  ⚠ 초기화 또는 reload 실패"
echo ""

# 5. 컨테이너 상태 확인
echo "▸ 5. 컨테이너 상태 점검"
sudo docker compose ps 2>/dev/null | grep -E "aegis-(nginx|proxy|redis|mongodb|soar-worker|detection-engine)" | \
  awk '{printf "  %-30s %s\n", $1, $4}'
echo ""

# 6. 핵심 엔드포인트 검증
echo "▸ 6. 핵심 엔드포인트 점검"

# nginx /health
NGINX_OK=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/health)
if [ "$NGINX_OK" = "200" ]; then
  echo "  ✓ nginx /health → 200"
else
  echo "  ✗ nginx /health → $NGINX_OK (점검 필요!)"
fi

# 사이드카 /health
SIDECAR_OK=$(sudo docker exec aegis-nginx wget -qO- http://localhost:4000/health 2>/dev/null | grep -c "ok")
if [ "$SIDECAR_OK" = "1" ]; then
  echo "  ✓ 사이드카 :4000 정상"
else
  echo "  ✗ 사이드카 :4000 점검 필요!"
fi

# Coraza 동작 확인
CORAZA_OK=$(curl -s -o /dev/null -w "%{http_code}" -G "http://localhost/" --data-urlencode "id=1' OR '1'='1")
if [ "$CORAZA_OK" = "403" ]; then
  echo "  ✓ Coraza WAF 동작 (SQLi 차단 확인)"
else
  echo "  ✗ Coraza WAF 점검 필요! 응답: $CORAZA_OK"
fi

# Risk Score Engine
RISK_OK=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5001/health 2>/dev/null)
if [ "$RISK_OK" = "200" ]; then
  echo "  ✓ Risk Score Engine 정상"
else
  echo "  ⚠ Risk Score Engine 응답: $RISK_OK"
fi

echo ""
echo "════════════════════════════════════════"
echo "  시연 준비 완료"
echo "════════════════════════════════════════"
echo ""
echo "  ./demo.sh 실행하면 시연 시작"
echo ""
