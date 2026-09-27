#!/bin/bash
# ============================================================
# Aegis-3 탐지 트리거 점검 (시연 전 리허설용, EC2 에서 실행)
#
#   ./check_detection.sh            # [1] 엔진 룰 트리거 + [2] E2E 이벤트 도달 점검
#   ./check_detection.sh engine     # [1]만 (detection-engine 단독, 부작용 없음)
#
# [1] detection-engine(:5001)에 룰별 대표 이벤트를 직접 POST → 기대한 rule_hits 가 나오는지.
#     매 실행마다 고유 IP/세션을 써서 이전 상태와 섞이지 않는다. Redis/Mongo/LLM 을 건드리지 않는다.
# [2] demo.sh 와 같은 요청을 nginx 로 보내고, 해당 이벤트가 Redis → worker → Mongo(traffic_logs)
#     까지 도달했는지, 어떤 event_type/level/rule_hits 로 저장됐는지 확인한다.
#     각 요청 query 에 고유 마커(chk=<RUN>)를 붙여 Mongo 에서 찾는다.
#     ⚠ 공격 요청은 X-Forwarded-For 로 문서 예약 IP(192.0.2.x)를 쓴다. AI_RULE_THRESHOLD 가
#       시연값(30)이면 이 IP 가 블랙리스트/CF 차단될 수 있으니 리허설 후 demo_cleanup.sh 실행.
# ============================================================

set -u
MODE="${1:-all}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENGINE="${ENGINE_URL:-http://localhost:5001}"
BASE="${BASE_URL:-http://localhost}"
HOST_HDR="Host: ${DEMO_HOST:-test.aegis3.cloud}"
RUN="chk$(date +%s)"
PASS=0; FAIL=0; WARN=0

G='\033[1;32m'; R='\033[1;31m'; Y='\033[1;33m'; C='\033[1;36m'; N='\033[0m'
ok()   { echo -e "  ${G}✓${N} $1"; PASS=$((PASS+1)); }
bad()  { echo -e "  ${R}✗${N} $1"; FAIL=$((FAIL+1)); }
warn() { echo -e "  ${Y}⚠${N} $1"; WARN=$((WARN+1)); }

# ------------------------------------------------------------
# [1] 엔진 룰 트리거
# ------------------------------------------------------------
analyze() {  # $1 = JSON body → stdout 응답
  curl -s -m 5 -X POST "$ENGINE/analyze" -H 'Content-Type: application/json' -d "$1"
}

expect_hit() {  # $1 설명, $2 기대 rule, $3 응답
  if echo "$3" | grep -q "\"$2\""; then ok "$1 → $2"; else bad "$1 → $2 기대, 응답: $(echo "$3" | head -c 300)"; fi
}

engine_checks() {
  echo -e "\n${C}[1] detection-engine 룰 트리거 ($ENGINE)${N}"
  if curl -fs -m 3 "$ENGINE/health" >/dev/null; then
    ok "/health 200 ($(curl -s "$ENGINE/health" | head -c 160))"
  else
    bad "/health 응답 없음 — detection-engine 컨테이너 확인"; return
  fi

  local n=$((RANDOM % 200 + 20)) ts
  local ip="198.51.100.$n" s="sess-$RUN"
  ts=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)

  # 민감 경로
  expect_hit "민감 경로 /.env" R-ASSET-001 \
    "$(analyze "{\"timestamp\":\"$ts\",\"ip\":\"$ip-a\",\"path\":\"/.env\",\"status_code\":200,\"analysis_profile\":\"full\",\"headers\":{\"x-forwarded-for\":\"$ip, 127.0.0.1\"}}")"

  # XFF 오탐 회귀: 프록시 체인 IP 만으로 SSRF 가 붙으면 안 됨
  local r
  r=$(analyze "{\"timestamp\":\"$ts\",\"ip\":\"$ip-x\",\"path\":\"/.env\",\"status_code\":200,\"analysis_profile\":\"full\",\"headers\":{\"x-forwarded-for\":\"$ip, 127.0.0.1\"}}")
  if echo "$r" | grep -q R-PAYLOAD-002; then bad "XFF(127.0.0.1) 만으로 SSRF 오탐 — 구버전 엔진이 배포돼 있음"; else ok "XFF 프록시 체인 IP 로 SSRF 오탐 없음"; fi

  # payload
  expect_hit "SSRF (메타데이터 URL)" R-PAYLOAD-002 \
    "$(analyze "{\"timestamp\":\"$ts\",\"ip\":\"$ip-b\",\"path\":\"/fetch\",\"query\":\"url=http://169.254.169.254/latest\",\"analysis_profile\":\"full\"}")"
  expect_hit "Path traversal" R-PAYLOAD-001 \
    "$(analyze "{\"timestamp\":\"$ts\",\"ip\":\"$ip-c\",\"path\":\"/download\",\"query\":\"f=../../etc/passwd\",\"analysis_profile\":\"full\"}")"
  expect_hit "Command injection" R-PAYLOAD-003 \
    "$(analyze "{\"timestamp\":\"$ts\",\"ip\":\"$ip-d\",\"path\":\"/ping\",\"query\":\"host=x;cat /etc/passwd\",\"analysis_profile\":\"full\"}")"

  # 경로 열거 15개 (60초 창)
  for i in $(seq 1 15); do
    r=$(analyze "{\"timestamp\":\"$ts\",\"ip\":\"$ip-e\",\"path\":\"/scan-$i\",\"status_code\":404,\"analysis_profile\":\"full\"}")
  done
  expect_hit "404 경로 열거 15개" R-SCAN-001 "$r"

  # BOLA 연속 ID 3개
  for i in 101 102 103; do
    r=$(analyze "{\"timestamp\":\"$ts\",\"ip\":\"$ip-f\",\"session_id\":\"$s-f\",\"user_id\":\"7\",\"target_user_id\":\"$i\",\"path\":\"/users/$i\",\"analysis_profile\":\"full\"}")
  done
  expect_hit "BOLA 권한 없는 객체 3개" R-BOLA-001 "$r"
  expect_hit "BOLA 연속 ID" R-BOLA-003 "$r"

  # 로그인 실패 10회
  for i in $(seq 1 10); do
    r=$(analyze "{\"timestamp\":\"$ts\",\"ip\":\"$ip-g\",\"session_id\":\"$s-g\",\"path\":\"/api/login\",\"status_code\":401,\"analysis_profile\":\"full\"}")
  done
  expect_hit "로그인 실패 10회" R-AUTH-001 "$r"

  # 요청량 150회 (rate_only)
  for i in $(seq 1 150); do
    r=$(analyze "{\"timestamp\":\"$ts\",\"ip\":\"$ip-h\",\"path\":\"/\",\"analysis_profile\":\"rate_only\"}")
  done
  expect_hit "요청량 150회/60초" R-RATE-001 "$r"
}

# ------------------------------------------------------------
# [2] E2E: nginx → (proxy|sidecar) → Redis → worker → Mongo
# ------------------------------------------------------------
mongo_eval() {
  sudo docker exec aegis-mongodb mongosh -u aegis_user -p "$MONGO_PASSWORD" \
    --authenticationDatabase admin aegis_logs --quiet --eval "$1" 2>/dev/null
}

find_event() {  # $1 marker → "event_type|level|score|rule_hits" (최대 15초 폴링)
  local q out
  q="const d=db.traffic_logs.find({'raw_event.query':{\$regex:'$1'}}).sort({_id:-1}).limit(1).toArray()[0];
     if(d){const s=d.security_analysis||{};print([d.raw_event.event_type,s.level,s.risk_score,(s.rule_hits||[]).join(',')].join('|'))}"
  for _ in $(seq 1 15); do
    out=$(mongo_eval "$q")
    [ -n "$out" ] && { echo "$out"; return; }
    sleep 1
  done
}

e2e_step() {  # $1 설명, $2 기대 HTTP, $3 기대 event_type(없으면 '-'), $4.. curl 인자
  local desc="$1" want_code="$2" want_type="$3"; shift 3
  local mark="${RUN}-$((PASS+FAIL+WARN))"
  local code got
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "$HOST_HDR" "$@" --data-urlencode "chk=$mark" -G "$BASE${E2E_PATH:-/}")
  got=$(find_event "$mark")
  local msg="$desc: HTTP $code"
  [ "$code" = "$want_code" ] || msg="$msg (기대 $want_code)"
  if [ -z "$got" ]; then
    if [ "$want_type" = "-" ]; then ok "$msg, 큐 이벤트 없음(기대대로)"; else bad "$msg, Mongo 에 이벤트 없음 (기대 $want_type)"; fi
  else
    IFS='|' read -r etype level score hits <<<"$got"
    if [ "$want_type" != "-" ] && [ "$etype" = "$want_type" ] && [ "$code" = "$want_code" ]; then
      ok "$msg → $etype / $level($score) / ${hits:-no-hits}"
    else
      warn "$msg → $etype / $level($score) / ${hits:-no-hits} (기대 ${want_type})"
    fi
  fi
}

e2e_checks() {
  echo -e "\n${C}[2] E2E 이벤트 도달 ($BASE, ${HOST_HDR#Host: })${N}"
  if [ -z "${MONGO_PASSWORD:-}" ] && [ -f "$REPO_ROOT/.env" ]; then
    MONGO_PASSWORD=$(grep -E '^MONGO_PASSWORD=' "$REPO_ROOT/.env" | cut -d= -f2-)
  fi
  [ -n "${MONGO_PASSWORD:-}" ] || { bad "MONGO_PASSWORD 없음 (.env 확인)"; return; }

  local th qlen
  th=$(sudo docker exec aegis-soar-worker printenv AI_RULE_THRESHOLD 2>/dev/null)
  qlen=$(sudo docker exec aegis-redis redis-cli LLEN aegis:security-events 2>/dev/null)
  echo "  (worker AI_RULE_THRESHOLD=${th:-?}, 큐 적체=${qlen:-?})"
  [ "${qlen:-0}" -gt 500 ] 2>/dev/null && warn "큐 적체 ${qlen}건 — 시연 이벤트가 늦게 반영될 수 있음"

  local ATK="X-Forwarded-For: 192.0.2.$((RANDOM % 200 + 20))"
  E2E_PATH=/index.html e2e_step "[A] 정상 요청" 200 access_event
  e2e_step "[C] SQLi (Coraza CRS)" 403 waf_blocked -H "$ATK" --data-urlencode "id=1' OR '1'='1"
  e2e_step "[D] XSS (Coraza CRS)" 403 waf_blocked -H "$ATK" --data-urlencode "q=<script>alert(1)</script>"
  # [E] demo.sh 는 허니팟 200 을 기대하지만, 커스텀 룰 130010(\.env)이 phase 1 에서 먼저 deny 하면
  #     403 + 큐 이벤트 없음이 된다(sidecar 는 949110/959100 차단 신호만 적재). 결과로 확인.
  E2E_PATH=/.env e2e_step "[E] /.env 허니팟" 200 honeypot_hit -H "$ATK"
  # 커스텀 룰(phase 1) 차단 요청이 대시보드/SOAR 에 남는지
  E2E_PATH=/actuator e2e_step "[+] /actuator (커스텀 룰 130001)" 403 waf_blocked -H "$ATK"
}

echo -e "${C}════ Aegis-3 탐지 트리거 점검 (run=$RUN) ════${N}"
engine_checks
[ "$MODE" = "engine" ] || e2e_checks

echo -e "\n${C}════ 결과: 통과 $PASS / 실패 $FAIL / 경고 $WARN ════${N}"
[ "$FAIL" -eq 0 ]
