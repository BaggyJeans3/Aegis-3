#!/bin/bash
# ============================================================
# Aegis-3 시연 후 운영 복구 스크립트 (사용자가 테스트 종료 후 직접 실행)
# 사용법: ./demo_restore.sh
#
# demo_setup.sh / demo.sh 가 런타임으로 약화시킨 보안 설정을
# 커밋된 운영 안전값으로 되돌린다.
#
#   복구 항목
#     1) nginx.conf / coraza.conf  → git checkout 으로 원복 (rate limit on, Coraza 풀룰)
#     2) soar-worker               → AI_RULE_THRESHOLD 운영 기본값(80)으로 재기동
#     3) 시연 데이터 정리           → Redis 큐/블랙리스트/클러스터, audit 로그, dynamic.conf
#
# [주의] nginx/ 디렉터리의 '커밋 안 한 다른 로컬 변경'도 git checkout 으로 사라진다.
#        운영 EC2 는 배포가 git reset --hard 라 평소 트리가 깨끗하므로 일반적으로 안전.
# ============================================================

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE="-f $REPO_ROOT/docker-compose.yml -f $REPO_ROOT/docker-compose.prod.yml"

echo "════════════════════════════════════════"
echo "  Aegis-3 운영 복구 (시연 → 운영)"
echo "  리포지토리: $REPO_ROOT"
echo "════════════════════════════════════════"
echo ""

# ------------------------------------------------------------
# 1. nginx 설정 원복 (rate limit 재활성화 + Coraza 차단룰 복원)
# ------------------------------------------------------------
echo "▸ 1. nginx 설정 git 원복 (rate limit on, Coraza 930130/130010 복원)"
( cd "$REPO_ROOT" && git checkout -- nginx/nginx.conf nginx/coraza.conf ) \
  && echo "  ✓ nginx.conf / coraza.conf 운영 버전으로 복원" \
  || echo "  ⚠ git checkout 실패 (리포지토리 경로/권한 확인)"

sudo docker exec aegis-nginx nginx -s reload 2>/dev/null \
  && echo "  ✓ nginx reload 완료" \
  || echo "  ⚠ nginx reload 실패 (nginx 미기동?)"
echo ""

# ------------------------------------------------------------
# 2. soar-worker AI 임계값 운영값(80)으로 재기동
#    (env 미지정 → docker-compose.yml 의 기본값 80 사용)
# ------------------------------------------------------------
echo "▸ 2. soar-worker AI_RULE_THRESHOLD 운영 기본값(80)으로 재기동"
( cd "$REPO_ROOT" && sudo docker compose $COMPOSE up -d --force-recreate --no-deps soar-worker ) \
  && echo "  ✓ soar-worker 재기동 (threshold=80)" \
  || echo "  ⚠ soar-worker 재기동 실패"
echo ""

# ------------------------------------------------------------
# 3. 시연 데이터 정리
# ------------------------------------------------------------
echo "▸ 3. 시연 데이터 정리 (Redis / audit / dynamic 룰)"

# 3-a. Redis 큐 + 블랙리스트 + 클러스터 캐시
sudo docker exec aegis-redis redis-cli DEL aegis:security-events > /dev/null 2>&1
sudo docker exec aegis-redis redis-cli KEYS "aegis:blacklist:*" \
  | xargs -r sudo docker exec -i aegis-redis redis-cli DEL > /dev/null 2>&1
sudo docker exec aegis-redis redis-cli KEYS "aegis:cluster:*" \
  | xargs -r sudo docker exec -i aegis-redis redis-cli DEL > /dev/null 2>&1
echo "  ✓ Redis 큐·블랙리스트·클러스터 캐시 정리"

# 3-b. Coraza audit 로그
sudo docker exec aegis-nginx truncate -s 0 /var/log/coraza/audit.log 2>/dev/null \
  && echo "  ✓ audit.log 비움"

# 3-c. AI 동적 룰 (시연 중 생성된 룰 제거)
sudo docker exec aegis-nginx truncate -s 0 /etc/nginx/rules/dynamic.conf 2>/dev/null \
  && sudo docker exec aegis-nginx nginx -s reload 2>/dev/null \
  && echo "  ✓ dynamic.conf 비우고 nginx reload"
echo ""

# ------------------------------------------------------------
# 4. 복구 검증
# ------------------------------------------------------------
echo "▸ 4. 복구 상태 검증"

# 4-a. rate limit 활성 확인 (nginx.conf 에 주석 아닌 limit_req 존재)
if grep -qE '^[[:space:]]*limit_req zone=aegis_per_ip' "$REPO_ROOT/nginx/nginx.conf"; then
  echo "  ✓ rate limit 활성"
else
  echo "  ✗ rate limit 비활성 — nginx.conf 확인 필요"
fi

# 4-b. Coraza 임시 제거룰이 사라졌는지 확인
if grep -q "SecRuleRemoveById 930130" "$REPO_ROOT/nginx/coraza.conf"; then
  echo "  ✗ Coraza 시연 제거룰이 아직 남아있음 — coraza.conf 확인 필요"
else
  echo "  ✓ Coraza 민감파일 차단룰 복원됨"
fi

# 4-c. /.env 가 다시 차단(403)되는지 (운영 정상)
ENV_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: test.aegis3.cloud" "http://localhost/.env" 2>/dev/null)
echo "  · /.env 응답 코드: $ENV_STATUS (운영 복구 시 403 또는 차단 기대)"

echo ""
echo "════════════════════════════════════════"
echo "  운영 복구 완료"
echo "════════════════════════════════════════"
echo ""
echo "  참고: 다음 배포(git reset --hard origin/main) 때도 운영 안전값으로 맞춰집니다."
echo ""
