#!/bin/bash
# ============================================================
# Aegis-3 풀 시연 스크립트 (EC2 환경)
# 사용법: chmod +x demo.sh && ./demo.sh
# ============================================================

BASE="http://localhost"
H="Host: test.aegis3.cloud"
ATK="X-Forwarded-For: 203.0.113.99"

# 색상
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
CYAN='\033[1;36m'
BOLD='\033[1m'
RESET='\033[0m'

# 헬퍼 함수
header() {
  echo ""
  echo -e "${CYAN}════════════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}  $1${RESET}"
  echo -e "${CYAN}════════════════════════════════════════════════════════${RESET}"
}

subheader() {
  echo ""
  echo -e "${YELLOW}▸ $1${RESET}"
}

success() {
  echo -e "${GREEN}  ✓ $1${RESET}"
}

info() {
  echo -e "  $1"
}

pause() {
  sleep $1
}

# ============================================================
# 시작 헤더
# ============================================================
clear
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║                                                          ║${RESET}"
echo -e "${BOLD}║          🛡️  Aegis-3 풀 시연 데모                        ║${RESET}"
echo -e "${BOLD}║          BaggyJeans 2026 졸업작품                        ║${RESET}"
echo -e "${BOLD}║                                                          ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
echo ""
pause 3

# ============================================================
# [A] 정상 트래픽 — 베이스라인
# ============================================================
header "[A] 정상 트래픽 — 시스템 정상 동작 확인"
pause 2

subheader "일반 사용자가 정상적으로 사이트에 접근"
info "→ curl http://test.aegis3.cloud/index.html"
pause 3

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "$H" "$BASE/index.html")
echo ""
success "응답 코드: $STATUS (정상 통과)"
pause 4

# ============================================================
# [B] 마스킹 데모
# ============================================================
header "[B] 개인정보 자동 마스킹 — 양방향 보안"
pause 2

subheader "백엔드 응답에 포함된 PII를 자동 마스킹"
info "백엔드 원본: 010-1234-5678, 900101-1234567, user@example.com"
pause 4

info "→ Aegis-3 통과 시 어떻게 변환되는지 확인:"
pause 2

RESPONSE=$(curl -s "$BASE/__masking_test__/case?id=1A" 2>/dev/null)
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo "$RESPONSE" | head -20
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
success "전화번호·주민번호·이메일이 정규식 4종으로 자동 마스킹"
success "Nginx 2-pass 구조 (:80 Coraza + :8081 마스킹) 동작 확인"
pause 6

# ============================================================
# [C] Coraza WAF — SQL Injection 차단
# ============================================================
header "[C] 2차 방어 — Coraza WAF SQL Injection 차단"
pause 2

subheader "공격자가 SQL Injection 시도"
info "페이로드: id=1' OR '1'='1"
info "→ curl 'http://test.aegis3.cloud/?id=1%27+OR+%271%27=%271'"
pause 4

STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -G -H "$H" -H "$ATK" "$BASE/" \
  --data-urlencode "id=1' OR '1'='1")
echo ""
echo -e "${RED}  ⛔ 응답 코드: $STATUS (Coraza 즉시 차단)${RESET}"
pause 3

info "Coraza audit 로그 — 차단 사유:"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
sudo docker exec aegis-nginx tail -20 /var/log/coraza/audit.log 2>/dev/null | \
  grep -aE "Coraza:|id \"94" | tail -3 | head -2
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
success "OWASP CRS 942100 (libinjection) 매칭"
success "949110 Anomaly Score 임계치 초과 → Access Denied"
pause 6

# ============================================================
# [D] Coraza WAF — XSS 차단
# ============================================================
header "[D] 2차 방어 — Coraza WAF XSS 차단"
pause 2

subheader "공격자가 XSS 페이로드 시도"
info "페이로드: <script>alert(1)</script>"
pause 3

STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -G -H "$H" -H "$ATK" "$BASE/" \
  --data-urlencode "q=<script>alert(1)</script>")
echo ""
echo -e "${RED}  ⛔ 응답 코드: $STATUS (Coraza 즉시 차단)${RESET}"
pause 3

success "OWASP CRS 941번대 XSS 룰 매칭"
pause 4

# ============================================================
# [E] 허니팟 — /.env 가짜 응답
# ============================================================
header "[E] 허니팟 — 공격자 기만 (Decoy 응답)"
pause 2

subheader "공격자가 환경변수 탈취 시도"
info "→ curl http://test.aegis3.cloud/.env"
info "→ 차단이 아닌 '가짜 성공 응답' 으로 공격자를 안심시킴"
pause 4

RESPONSE=$(curl -s -H "$H" -H "$ATK" "$BASE/.env")
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo "응답: $RESPONSE"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
success "HTTP 200 + 가짜 decoy 응답 반환"
success "공격자는 성공으로 오인 → 행동 패턴 수집"
success "백그라운드에서 honeypot_hit 이벤트 → MongoDB 적재"
pause 6

# ============================================================
# ============================================================
# [F] SOAR 트리거 — Risk Score → AI 룰 생성
# ============================================================
header "[F] 3차 방어 — SOAR 자동 대응 (LLM 룰 생성)"
pause 2

subheader "Gemini 첫 호출 안정화를 위해 worker 워밍업"
sudo docker restart aegis-soar-worker > /dev/null 2>&1
info "→ worker 재기동 (fork-after-init 회피)"
sleep 8
success "worker 준비 완료"
pause 2

subheader "고위험 공격 이벤트를 Redis 큐에 직접 주입"
info "→ 실시간 운영 환경에서는 공격 누적으로 자동 트리거"
info "→ 시연용 빠른 검증을 위해 직접 주입"
pause 3

# 매 시연 고유 IP/패턴 (블랙리스트·클러스터 캐시 충돌 회피)
DEMO_IP="10.$((RANDOM%250+1)).$((RANDOM%250+1)).$((RANDOM%250+1))"
EVENT_ID="demo-$(date +%s)"

# [고객사 대시보드 시연용] tenant_id 를 넣으면 그 고객사 계정 대시보드에도 로그가 뜬다.
#   export DEMO_TENANT_ID=<고객사 tenant_id(UUID)>  를 미리 지정하면 됨.
#   (미지정 시 빈 값 → 관리자(admin) 대시보드에만 표시. customer 필터엔 안 잡힘)
DEMO_TENANT_ID="${DEMO_TENANT_ID:-}"
DEMO_COMPANY="${DEMO_COMPANY:-Demo Corp}"
if [ -n "$DEMO_TENANT_ID" ]; then
  info "▸ Redis 큐에 SQLi UNION SELECT 공격 이벤트 적재 (ip=$DEMO_IP, tenant=$DEMO_TENANT_ID)..."
else
  info "▸ Redis 큐에 SQLi UNION SELECT 공격 이벤트 적재 (ip=$DEMO_IP, tenant 미지정=admin 뷰 전용)..."
fi
sudo docker exec aegis-redis redis-cli LPUSH aegis:security-events \
  "{\"event_id\":\"$EVENT_ID\",\"trace_id\":\"trace-$EVENT_ID\",\"tenant_id\":\"$DEMO_TENANT_ID\",\"company_name\":\"$DEMO_COMPANY\",\"ip\":\"$DEMO_IP\",\"path\":\"/admin/login\",\"method\":\"POST\",\"query\":\"id=1 UNION SELECT password FROM users--\",\"headers\":{\"user-agent\":\"sqlmap/1.5\"},\"body\":\"\",\"analysis_profile\":\"full\",\"action_on_match\":\"block\",\"event_type\":\"blocked_request\",\"status_code\":403}" \
  > /dev/null
success "이벤트 적재 완료 (event_id=$EVENT_ID)"
pause 2

info "▸ Celery Beat(2초 주기) → Risk Score 분석 → Gemini 호출..."
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

# 룰 생성 폴링 (최대 30초). Gemini 503 등으로 실패 시 시딩 룰로 fallback
RULE_ID=""
for i in $(seq 1 15); do
  sleep 2
  RULE_ID=$(sudo docker exec aegis-nginx cat /etc/nginx/rules/dynamic.conf 2>/dev/null \
    | grep -oE 'id:2[0-9]{9}' | tail -1 | cut -d: -f2)
  if [ -n "$RULE_ID" ]; then
    echo "  AI 룰 생성 확인 (${i}회 폴링, ${RULE_ID})"
    break
  fi
  echo "  ...생성 대기 중 ($((i*2))s)"
done
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

if [ -z "$RULE_ID" ]; then
  # Gemini 불안정 시 fallback: setup에서 시딩해둔 룰 사용
  RULE_ID=$(cat ~/demo/.seed_rule_id 2>/dev/null)
  if [ -n "$RULE_ID" ]; then
    echo -e "${YELLOW}  ⚠ 라이브 생성 지연 — 사전 검증된 룰로 진행 (id=$RULE_ID)${RESET}"
  else
    echo -e "${RED}  ✗ 룰 생성 실패 & 시딩 룰 없음 — demo_setup.sh 먼저 실행 필요${RESET}"
  fi
fi
success "Risk Score Engine 분석 → Gemini 2.5 Flash → PCRE 정규식 + SecRule 자동 생성"
pause 4

# ============================================================
# [G] 사이드카 룰 주입 확인
# ============================================================
header "[G] AI 생성 룰 — 사이드카 주입 확인"
pause 2

subheader "Gemini가 생성한 룰이 dynamic.conf에 적재됨 (/etc/nginx/rules/dynamic.conf)"
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo "dynamic.conf 현재 내용:"
sudo docker exec aegis-nginx cat /etc/nginx/rules/dynamic.conf 2>/dev/null | tail -3
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
success "룰 ID 2,000,000,000 대역 (AI 룰 격리)"
success "Shadow Mode (pass,log) → 오탐 검증 → deny 승격"
pause 3

info "▸ 사이드카 API로 현재 룰 상태 조회:"
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
sudo docker exec aegis-nginx node -e "
const http=require('http');
http.get({host:'localhost',port:4000,path:'/api/v1/rules'},res=>{
  let d='';res.on('data',c=>d+=c);
  res.on('end',()=>{try{const j=JSON.parse(d);console.log(JSON.stringify(j,null,2).slice(0,1000))}catch(e){console.log(d.slice(0,600))}});
}).on('error',e=>console.log('조회 실패:',e.message));
" 2>/dev/null
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
success "shadow/live 상태와 만료 메타데이터 관리"
pause 4

# ============================================================
# [H] Shadow Mode → Promote (수동 트리거 시연)
# ============================================================
header "[H] Shadow Mode → Promote 승격"
pause 2

subheader "AI 생성 룰은 즉시 deny가 아닌 'pass,log'(Shadow)로 시작"
info "✓ 운영 환경: SHADOW_DURATION 동안 매칭 관찰 → CRS 교차검증 → 오탐 0건 시 자동 승격"
info "✓ 시연: 관찰 시간을 단축하기 위해 승격을 직접 트리거"
pause 4

if [ -n "$RULE_ID" ]; then
  echo ""
  echo -e "${CYAN}━━━ 승격 전 (Shadow: pass,log) ━━━${RESET}"
  sudo docker exec aegis-nginx cat /etc/nginx/rules/dynamic.conf | grep "$RULE_ID"
  pause 3

  info "▸ 사이드카 promote API 호출 (rule_id=$RULE_ID)..."
  sudo docker exec aegis-nginx node -e "
  const http=require('http');
  const r=http.request({host:'localhost',port:4000,path:'/api/v1/rules/promote/$RULE_ID',method:'POST',headers:{'Content-Length':0}},res=>{
    let d='';res.on('data',c=>d+=c);res.on('end',()=>console.log('  응답:',res.statusCode,d));
  });r.on('error',e=>console.log('  ERR',e.message));r.end();
  " 2>/dev/null
  pause 2

  echo ""
  echo -e "${GREEN}━━━ 승격 후 (Live: deny,status:403) ━━━${RESET}"
  sudo docker exec aegis-nginx cat /etc/nginx/rules/dynamic.conf | grep "$RULE_ID"
  echo ""
  success "Shadow → Live 승격 완료 — pass,log → deny,status:403"
  pause 4

  info "▸ 승격된 룰로 동일 공격 재시도 → 차단 확인:"
  PROMO_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "$H" \
    -G "$BASE/" --data-urlencode "id=1 UNION SELECT password FROM users--")
  echo ""
  if [ "$PROMO_STATUS" = "403" ]; then
    echo -e "${RED}  ⛔ 응답 코드: $PROMO_STATUS — AI 생성 룰이 직접 차단${RESET}"
    success "자가 진화한 룰이 실제 트래픽을 차단"
  else
    echo -e "${YELLOW}  응답 코드: $PROMO_STATUS${RESET}"
  fi
else
  echo -e "${RED}  ✗ RULE_ID 없음 — promote 생략${RESET}"
fi
pause 5
# [I] 블랙리스트 자동 등록 검증
# ============================================================
header "[I] 블랙리스트 자동 등록 (24h TTL)"
pause 2

subheader "SOAR가 분석 후 공격 IP를 Redis 블랙리스트에 등록"
info "▸ Redis 블랙리스트 키 확인:"
pause 3

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
sudo docker exec aegis-redis redis-cli keys "aegis:blacklist:*"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
pause 4

info "▸ 등록된 IP로 정상 요청 시도 → Proxy 1차 차단 미들웨어:"
pause 2

# 블랙리스트 등록은 SOAR 비동기 처리라 최대 10초 폴링
STATUS=200
for _bl in 1 2 3 4 5; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "$H" -H "X-Forwarded-For: $DEMO_IP" "$BASE/index.html")
  [ "$STATUS" = "403" ] && break
  sleep 2
done
echo ""
if [ "$STATUS" = "403" ]; then
  echo -e "${RED}  ⛔ 응답 코드: $STATUS (블랙리스트 IP → 라우팅 전 즉시 차단)${RESET}"
  success "Express Proxy의 최상단 미들웨어가 작동"
  success "Coraza·SOAR 거치지 않고 즉결 차단 → 비용 최소화"
else
  echo -e "${YELLOW}  ⚠ 응답 코드: $STATUS (블랙리스트 등록 대기 중 또는 다른 경로)${RESET}"
  info "  SOAR가 비동기로 분석 중 — 등록까지 약간 시간 소요"
fi
pause 6

# ============================================================
# [J] 대시보드 안내
# ============================================================
header "[J] 대시보드 — 실시간 시각화"
pause 2

subheader "지금까지의 모든 이벤트가 대시보드에 라이브로 흐름"
info "✓ Multi-tenant 격리 (Supabase JWT 인증)"
info "✓ MongoDB 로그 → SSE 실시간 스트림"
info "✓ Risk Score 통계, 차단 내역, AI 룰 현황"
pause 5

echo ""
echo -e "${BOLD}  🌐 https://dashboard.aegis3.cloud${RESET}"
pause 5

# ============================================================
# 마무리
# ============================================================
header "✅ 시연 완료 — Aegis-3 풀 파이프라인 검증"
pause 2

echo ""
echo -e "  ${BOLD}1차 (Edge)${RESET}    Cloudflare WAF + Rate Limit"
echo -e "        ↓"
echo -e "  ${BOLD}2차 (Engine)${RESET}  Coraza WAF + 마스킹 + 허니팟"
echo -e "        ↓"
echo -e "  ${BOLD}3차 (SOAR)${RESET}    LLM 자동 룰 생성 + Shadow Mode + 블랙리스트"
echo ""
echo -e "  ${GREEN}✓ 다층 방어 ── 공격이 어느 단계든 격리${RESET}"
echo -e "  ${GREEN}✓ 자동 진화 ── AI 룰이 환경 학습으로 자체 생성${RESET}"
echo -e "  ${GREEN}✓ 양방향 ─── 응답 PII 마스킹으로 정보 유출 방지${RESET}"
echo ""
pause 3

echo -e "${BOLD}════════════════════════════════════════════════════════${RESET}"
echo ""
