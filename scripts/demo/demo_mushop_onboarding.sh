#!/bin/bash
# ============================================================
# Aegis-3 고객사 자동 온보딩 시연 스크립트 (MuShop)
# 사용법: chmod +x demo_mushop_onboarding.sh && ./demo_mushop_onboarding.sh
#
# demo.sh(전체 파이프라인 시연)와 별개로, 명세 제출만으로 라우팅·허니팟이
# 자동 생성되는 온보딩 부분만 보여준다.
#
# 전제: docker compose 로 전체 스택이 떠 있어야 함 (aegis-postgres, aegis-proxy,
#       aegis-portal-backend, aegis-nginx).
# ============================================================

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SPEC_FILE="$REPO_ROOT/data/specs/mushop_openapi_example.json"
# 환경변수로 덮어쓸 수 있다. 기본값은 로컬 개발(nginx 8080) 기준.
# EC2 운영(nginx 80, 실제 도메인) 예:
#   OWNER_USER_ID=<고객사 계정 Supabase UUID> DOMAIN=mushop.aegis3.cloud NGINX_URL=http://localhost \
#     bash scripts/demo/demo_mushop_onboarding.sh
DOMAIN="${DOMAIN:-mushop.aegis3.local}"
ORIGIN="${ORIGIN:-http://140.245.69.134}"          # 오라클에 올라간 MuShop 실제 서버
NGINX_URL="${NGINX_URL:-http://localhost:8080}"    # Aegis 입구(nginx). EC2 는 http://localhost
# MuShop 테넌트 소유자(Supabase auth.users.id, UUID). 비우면 소유자 NULL 로 등록되어
# 고객사 대시보드(소유 tenant 필터)에서 로그가 보이지 않고 관리자 화면에서만 보인다.
OWNER_USER_ID="${OWNER_USER_ID:-}"
H="Host: $DOMAIN"

GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
CYAN='\033[1;36m'
BOLD='\033[1m'
RESET='\033[0m'

header() {
  echo ""
  echo -e "${CYAN}════════════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}  $1${RESET}"
  echo -e "${CYAN}════════════════════════════════════════════════════════${RESET}"
}
subheader() { echo ""; echo -e "${YELLOW}▸ $1${RESET}"; }
success()   { echo -e "${GREEN}  ✓ $1${RESET}"; }
fail()      { echo -e "${RED}  ✗ $1${RESET}"; }
info()      { echo "  $1"; }
pause()     { sleep "$1"; }

clear
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║   🛡️  Aegis-3 — 신규 고객사 자동 온보딩 시연 (MuShop)     ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
pause 2

if [ -z "$OWNER_USER_ID" ]; then
  echo -e "${YELLOW}  ⚠ OWNER_USER_ID 미지정 — MuShop 이 소유자 없이 등록되어 고객사 대시보드에서는 로그가 안 보입니다 (관리자 화면만 표시).${RESET}"
  pause 2
fi

# ============================================================
# [A] 기존 데이터 정리 (재실행 가능하도록)
# ============================================================
header "[A] 사전 정리 — 기존 MuShop 등록 제거"
# 이전 시연이 만든 행(소유자 없음 또는 이번에 지정한 소유자)만 지운다.
# company_name 만으로 지우면 다른 고객 계정이 소유한 실제 MuShop 테넌트까지 삭제된다.
if [[ -n "$OWNER_USER_ID" && ! "$OWNER_USER_ID" =~ ^[0-9a-fA-F-]{36}$ ]]; then
  fail "OWNER_USER_ID 가 UUID 형식이 아닙니다: $OWNER_USER_ID"
  exit 1
fi
OWNER_COND="supabase_user_id IS NULL"
[ -n "$OWNER_USER_ID" ] && OWNER_COND="($OWNER_COND OR supabase_user_id = '$OWNER_USER_ID')"
sudo docker exec -i aegis-postgres psql -U aegis_admin -d aegis_proxy > /dev/null 2>&1 <<SQL
DELETE FROM routers WHERE tenant_id IN (SELECT tenant_id FROM tenants WHERE company_name = 'MuShop' AND $OWNER_COND);
DELETE FROM tenants WHERE company_name = 'MuShop' AND $OWNER_COND;
SQL
success "이전 시연 데이터 정리 완료 (재실행 대비)"
pause 2

# ============================================================
# [B] 고객사 온보딩 — OpenAPI 스펙 제출 → 자동 등록
# ============================================================
header "[B] 신규 고객사 온보딩 — 사람 개입 없이 자동 등록"
pause 1

subheader "MuShop이 제출한 API 명세(OpenAPI JSON)"
info "→ $SPEC_FILE"
echo ""
cat "$SPEC_FILE" | head -20
echo "  ..."
pause 3

subheader "등록 API 호출 (services/aegis-portal-backend: spec_text 파싱 → routers 자동 생성)"
sudo docker cp "$SPEC_FILE" aegis-portal-backend:/tmp/mushop_spec.json > /dev/null

RESULT=$(sudo docker exec aegis-portal-backend python -c "
import asyncio, json
from app.postgres import connect_to_postgres, close_postgres_connection
from app.customers import create_customer

async def main():
    await connect_to_postgres()
    with open('/tmp/mushop_spec.json', encoding='utf-8') as f:
        spec_text = f.read()
    result = await create_customer(
        company_name='MuShop',
        plan_type='FREE',
        spec_text=spec_text,
        supabase_user_id='${OWNER_USER_ID:-demo-onboarding}',
        inbound_domain='$DOMAIN',
        target_origin='$ORIGIN',
    )
    print(json.dumps(result, ensure_ascii=False))
    await close_postgres_connection()

asyncio.run(main())
")

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo "$RESULT" | python -m json.tool 2>/dev/null || echo "$RESULT"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

ROUTE_COUNT=$(echo "$RESULT" | grep -oE '"router_count": ?[0-9]+' | grep -oE '[0-9]+')
PARSED_COUNT=$(echo "$RESULT" | grep -oE '"parsed_route_count": ?[0-9]+' | grep -oE '[0-9]+')

if [ -n "$ROUTE_COUNT" ]; then
  success "명세 ${PARSED_COUNT}개 경로 파싱 → 구체 라우트 + 캐치올 + 허니팟 총 ${ROUTE_COUNT}개 자동 생성"
else
  fail "등록 실패 — portal-backend 로그 확인 필요"
fi
pause 3

subheader "프록시 라우트 캐시 갱신 (최대 30초 자동, 시연용으로 즉시 재기동)"
sudo docker restart aegis-proxy > /dev/null 2>&1
sleep 3
# nginx는 proxy_pass http://proxy:3000 를 시작 시 IP로 캐싱한다. aegis-proxy 재기동으로
# 컨테이너 IP가 바뀌면 nginx가 옛 IP를 계속 참조해 502가 나므로, reload로 재해석시킨다.
sudo docker exec aegis-nginx nginx -s reload > /dev/null 2>&1
sleep 1
success "라우트 캐시 반영 완료"
pause 2

# ============================================================
# [C] 실제 API — 등록 즉시 정상 프록시
# ============================================================
header "[C] 실제 트래픽 — 등록 즉시 MuShop으로 정상 프록시"
pause 1

subheader "고객: 상품 목록 조회"
info "→ curl -H \"$H\" $DOMAIN/api/catalogue"
STATUS=$(curl -s -o /tmp/mushop_demo_resp.json -w "%{http_code}" -H "$H" "$NGINX_URL/api/catalogue")
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
head -c 200 /tmp/mushop_demo_resp.json; echo "..."
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
if [ "$STATUS" = "200" ]; then
  success "응답 코드: $STATUS — MuShop 실제 상품 데이터 수신"
else
  fail "응답 코드: $STATUS"
fi
pause 4

# ============================================================
# [D] 가짜 경로 — 명세에 없는 경로는 자동으로 허니팟
# ============================================================
header "[D] 가짜 경로 자동 생성 — 명세에 없는 경로는 공격자 유인"
pause 1

subheader "공격자: 존재하지 않는 백업/설정 API 스캔 시도"
info "→ curl -H \"$H\" $DOMAIN/api/backup"
RESPONSE=$(curl -s -H "$H" "$NGINX_URL/api/backup")
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "$H" "$NGINX_URL/api/backup")
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo "응답: $RESPONSE"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
if [ "$STATUS" = "200" ]; then
  success "응답 코드: $STATUS — 차단 대신 가짜 성공 응답 (공격자 행동 패턴 수집)"
  success "MuShop 명세엔 없던 경로 — 등록 시 자동 생성된 디코이"
else
  fail "응답 코드: $STATUS"
fi
pause 4

subheader "공격자: 민감 파일 접근 시도 (.env) — 1차 WAF가 먼저 차단"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "$H" "$NGINX_URL/.env")
echo ""
if [ "$STATUS" = "403" ]; then
  echo -e "${RED}  ⛔ 응답 코드: $STATUS (Coraza WAF 1차 차단)${RESET}"
  success "명세에 없는 경로라도, 민감 패턴은 WAF가 허니팟보다 먼저 처리 (다층 방어)"
fi
pause 4

# ============================================================
# 마무리
# ============================================================
header "✅ 온보딩 시연 완료"
pause 1
echo ""
echo -e "  ${BOLD}입력${RESET}     고객사가 OpenAPI 명세 제출"
echo -e "        ↓"
echo -e "  ${BOLD}자동 생성${RESET} 구체 라우트 + 캐치올 + 디코이(허니팟) — 사람 개입 없음"
echo -e "        ↓"
echo -e "  ${BOLD}즉시 반영${RESET} 등록 직후 실제 트래픽 정상 프록시 + 미등록 경로 자동 유인"
echo ""
echo -e "  ${GREEN}✓ 고객사가 몇 명이든 동일한 흐름 — 코드 수정 없이 스펙만 제출${RESET}"
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════${RESET}"
echo ""
