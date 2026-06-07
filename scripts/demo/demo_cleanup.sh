#!/bin/bash
# ============================================================
# Aegis-3 시연 후 정리 스크립트
# 사용법: ./demo_cleanup.sh
# ============================================================

echo "════════════════════════════════════════"
echo "  시연 환경 정리"
echo "════════════════════════════════════════"
echo ""

# 1. Redis 정리
echo "▸ Redis 시연 데이터 정리"
sudo docker exec aegis-redis redis-cli DEL aegis:security-events > /dev/null
sudo docker exec aegis-redis redis-cli KEYS "aegis:blacklist:203.0.113.99" | xargs -r sudo docker exec -i aegis-redis redis-cli DEL > /dev/null 2>&1
sudo docker exec aegis-redis redis-cli KEYS "aegis:cluster:*" | xargs -r sudo docker exec -i aegis-redis redis-cli DEL > /dev/null 2>&1
echo "  ✓ 시연 IP 블랙리스트 + 클러스터 캐시 삭제"
echo ""

# 2. audit 로그 정리
echo "▸ audit 로그 truncate"
sudo docker exec aegis-nginx truncate -s 0 /var/log/coraza/audit.log 2>/dev/null && \
  echo "  ✓ audit.log 비움"
echo ""

# 3. AI 룰 정리 (시연용 룰만)
echo "▸ AI 동적 룰 정리"
sudo docker exec aegis-nginx truncate -s 0 /etc/nginx/rules/dynamic.conf 2>/dev/null && \
  sudo docker exec aegis-nginx nginx -s reload 2>/dev/null && \
  echo "  ✓ dynamic.conf 비우고 nginx reload"
echo ""

echo "════════════════════════════════════════"
echo "  정리 완료"
echo "════════════════════════════════════════"
echo ""
echo "  운영 복구 안내:"
echo "  - SHADOW_DURATION 등 시연용 값을 원복하려면 docker-compose.yml 편집 후"
echo "    docker compose up -d --force-recreate nginx"
echo "  - rate limit 복구는 이미 끝났음 (nginx.conf 96번 활성)"
echo ""
