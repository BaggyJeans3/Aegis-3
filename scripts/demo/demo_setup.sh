#!/bin/bash
# ============================================================
# Aegis-3 시연 환경 사전 준비 스크립트
# 사용법: ./demo_setup.sh
# ============================================================

echo "════════════════════════════════════════"
echo "  Aegis-3 시연 환경 준비 시작"
echo "════════════════════════════════════════"
echo ""

# 1. SHADOW_DURATION 짧게 설정 (시연용)
echo "▸ 1. 시연용 환경변수 적용 안내"
echo "  → docker-compose.yml의 nginx 서비스에 추가 권장:"
echo "    environment:"
echo "      SHADOW_DURATION: 30        # 5분 → 30초"
echo "      TTL_SECONDS: 60             # 24h → 60초"
echo "      MIN_SHADOW_SAMPLES: 1"
echo ""
echo "  → 적용 후: docker compose up -d --force-recreate nginx"
echo ""
echo "  (이미 적용된 경우 무시)"
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
