const express = require('express')
const fs = require('fs')
const { exec } = require('child_process')
const path = require('path')
const Tail = require('tail').Tail
const redis = require('redis')

const app = express()
const port = parseInt(process.env.SIDECAR_PORT || '4000', 10)
const SHADOW_DURATION = parseInt(process.env.SHADOW_DURATION || '300', 10)
const TTL_SECONDS = parseInt(process.env.TTL_SECONDS || '86400', 10) // idle 만료(무매칭 시)
// 하이브리드 TTL 절대 상한: 매칭이 계속돼도 이 시간이 지나면 강제 만료·재평가.
// idle(TTL_SECONDS)보다 충분히 커야 sliding 효과가 의미 있음. 기본 7일.
const MAX_RULE_AGE_SECONDS = parseInt(
  process.env.MAX_RULE_AGE_SECONDS || '604800',
  10,
)
const CLEANUP_INTERVAL = parseInt(process.env.CLEANUP_INTERVAL || '60', 10)
const AUDIT_LOG_PATH = process.env.AUDIT_LOG_PATH || '/var/log/coraza/audit.log'
const rulePath = process.env.RULE_FILE || '/etc/nginx/rules/dynamic.conf'
const nginxBin = process.env.NGINX_BIN || '/usr/sbin/nginx'
// 폐기된 룰 보관 파일(nginx 가 include 하지 않는 별도 파일). 물리 삭제 대신 여기에 보관해
// 재공격 시 LLM 재생성 없이 재무장(re-arm)하고, 폐기 근거를 추적한다.
const RULE_ARCHIVE_FILE =
  process.env.RULE_ARCHIVE_FILE || '/etc/nginx/rules/archived.conf'
// Shadow 승격 최소 표본: '공격 확정' 매칭이 이 건수 미만이면 승격하지 않는다.
// (과거: 매칭 0건도 FP=0 이라 자동 승격 → 검증 안 된 룰이 deny 로 올라가는 위험)
const MIN_SHADOW_SAMPLES = parseInt(process.env.MIN_SHADOW_SAMPLES || '1', 10)
// 표본 부족 시 shadow 관찰을 연장하는 절대 상한. 이 시간까지도 표본이 모자라면 보관 처리.
// SHADOW_DURATION 보다 충분히 커야 연장이 의미 있음. 기본 1시간.
const SHADOW_MAX_DURATION = parseInt(
  process.env.SHADOW_MAX_DURATION || '3600',
  10,
)
// nginx reload 디바운스(ms): 짧은 시간에 몰린 룰 변경을 모아 reload 1회로 합산.
const RELOAD_DEBOUNCE_MS = parseInt(process.env.RELOAD_DEBOUNCE_MS || '2000', 10)

// AI 동적 룰 ID 대역 (README 기준). 이 밖의 매칭 룰(CRS 9xxxxx·정적 커스텀)은
// 사람이 검증한 룰이라 Shadow 판정의 교차검증(C) 신호로 신뢰한다.
const AI_RULE_ID_MIN = 2000000000
const AI_RULE_ID_MAX = 2099999999

// ── [차단 로그 적재] Coraza 가 차단(deny)한 요청을 MongoDB 로 보내기 위한 설정 ──
// 차단 판정 신호: CRS 익명점수 차단룰(949110 inbound / 959100 outbound)이 매칭됐다 =
// 익명점수 임계 초과로 요청이 deny 됐다는 의미. 이 룰이 보이면 '차단된 공격'으로 본다.
// proxy 가 못 보는(엣지에서 끊긴) SQLi/XSS 등을 여기서 잡아 worker→Mongo 로 흘려보낸다.
const BLOCK_SIGNAL_RULE_IDS = (process.env.BLOCK_SIGNAL_RULE_IDS || '949110,959100')
  .split(',')
  .map((s) => parseInt(s.trim(), 10))
  .filter((n) => !isNaN(n))
// proxy/worker 와 동일한 큐. worker(consume_logs_from_redis_queue)가 RPOP 해서 저장한다.
const SECURITY_EVENT_QUEUE =
  process.env.SECURITY_EVENT_QUEUE || 'aegis:security-events'

// Shadow 판정 B(IP 평판)용 Redis. 연결 실패해도 핵심기능은 계속(fail-open: B 생략=C만).
const REDIS_HOST = process.env.REDIS_HOST || 'redis'
const REDIS_PORT = parseInt(process.env.REDIS_PORT || '6379', 10)
let redisReady = false
const redisClient = redis.createClient({
  socket: { host: REDIS_HOST, port: REDIS_PORT },
})
redisClient.on('ready', () => {
  redisReady = true
  console.log(
    `[Sidecar] Redis 연결됨 (${REDIS_HOST}:${REDIS_PORT}) — Shadow B(IP 평판) 활성`,
  )
})
redisClient.on('error', () => {
  redisReady = false
})
redisClient.connect().catch((err) => {
  console.warn(
    `[Sidecar] Redis 연결 실패: ${err.message} — Shadow 판정은 C(CRS 교차검증)만 사용`,
  )
})

// Shadow Mode 중인 룰들
const shadowRules = new Map() // rule_id → { startedAt, ruleText, expiresAt }
// shadow 매칭 분류 통계: total=총매칭, attack=공격 확정, fp=오탐 의심
const shadowStats = new Map() // rule_id → { total, attack, fp }

// 승격된 라이브 룰들
const liveRules = new Map() // rule_id → { promotedAt, lastMatchedAt }

// 폐기(revoke)된 룰 보관소: 물리 삭제 대신 보관 → 재공격 시 LLM 재생성 없이 재무장 가능.
// 프로세스 재시작 시 메모리는 사라지지만 파일(RULE_ARCHIVE_FILE)에는 영구 기록된다.
const archivedRules = new Map() // rule_id → { ruleText, reason, archivedAt }

// 시작 시 audit log 파일이 없으면 빈 파일로 만들어둠 (Tail 패키지가 에러 안 내게)
try {
  fs.mkdirSync(path.dirname(AUDIT_LOG_PATH), { recursive: true })
  if (!fs.existsSync(AUDIT_LOG_PATH)) {
    fs.writeFileSync(AUDIT_LOG_PATH, '')
  }
} catch (err) {
  console.error('[Sidecar] audit log init failed:', err.message)
}

// 보관 파일 디렉터리 보장(룰 디렉터리와 동일하지만, 부팅 순서와 무관하게 안전하게)
try {
  fs.mkdirSync(path.dirname(RULE_ARCHIVE_FILE), { recursive: true })
} catch (err) {
  console.error('[Sidecar] archive dir init failed:', err.message)
}

app.use(express.json({ limit: '256kb' }))

app.get('/health', (_req, res) => res.json({ ok: true, rule_file: rulePath }))

// 룰 액션 문자열의 중복 log/auditlog 토큰을 정리한다.
// deny↔pass 변환을 inject/promote/rearm 에서 반복하면 ',log,auditlog' 가 매번
// 덧붙어 불어나므로(재무장 반복 시 누적), 각 변환 직후 이 함수로 첫 토큰만 남긴다.
function dedupeAction(ruleStr, tok) {
  let seen = false
  return ruleStr.replace(new RegExp(`,${tok}\\b`, 'g'), (m) => {
    if (seen) return ''
    seen = true
    return m
  })
}
function normalizeRuleActions(ruleStr) {
  // auditlog 를 먼저(‘log’ 가 ‘auditlog’ 의 접미사라 ,log\b 는 ,auditlog 를 건드리지 않음)
  return dedupeAction(dedupeAction(ruleStr, 'auditlog'), 'log')
}

app.post('/api/v1/rules/inject', (req, res) => {
  const newRule = req.body && req.body.rule
  if (!newRule || typeof newRule !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid "rule" field' })
  }

  // 1. 룰 텍스트에서 rule_id 추출
  const idMatch = newRule.match(/id:(\d+)/)
  if (!idMatch) {
    return res.status(400).json({ error: 'Rule text must contain id:<number>' })
  }
  const ruleId = parseInt(idMatch[1], 10)

  // 이미 등록된 룰 ID면 거부 (중복 방지)
  if (shadowRules.has(ruleId) || liveRules.has(ruleId)) {
    return res.status(409).json({ error: `Rule ${ruleId} already exists` })
  }
  // 같은 ID 가 보관소에 있으면 새 주입이 보관본을 대체 → 메모리에서 정리(파일 기록은 유지)
  if (archivedRules.has(ruleId)) {
    console.log(`[Sidecar] re-inject ${ruleId}: 기존 보관본 대체`)
    archivedRules.delete(ruleId)
  }

  // 2. deny 액션을 pass,log로 강제 변환 (Shadow Mode)
  const shadowRule = normalizeRuleActions(
    newRule.replace(/\bdeny\b/, 'pass,log,auditlog').replace(/,status:\d+/, ''),
  )

  // 3. 룰 파일에 추가
  try {
    fs.appendFileSync(rulePath, shadowRule + '\n')
  } catch (err) {
    console.error('[Sidecar] rule write failed:', err.message)
    return res
      .status(500)
      .json({ error: 'Rule write failed', detail: err.message })
  }
  console.log(`[Sidecar] rule appended (shadow): id=${ruleId}`)

  // 4. shadowRules에 등록 (이게 핵심)
  shadowRules.set(ruleId, {
    startedAt: Date.now(),
    ruleText: shadowRule,
    expiresAt: Date.now() + TTL_SECONDS * 1000, // 참고용 메타데이터
  })
  shadowStats.set(ruleId, { total: 0, attack: 0, fp: 0 })
  console.log(`[Shadow] injected ${ruleId} (will judge in ${SHADOW_DURATION}s)`)

  // 5. nginx reload (배치). 룰은 파일+메모리에 이미 반영됨, 적용만 합산 지연.
  scheduleReload()
  return res.json({ status: 'shadow_injected', rule_id: ruleId, reload: 'queued' })
})

app.post('/api/v1/rules/promote/:id', (req, res) => {
  const ruleId = parseInt(req.params.id, 10)
  if (isNaN(ruleId)) {
    return res.status(400).json({ error: 'Invalid rule_id' })
  }
  const ok = promoteRule(ruleId)
  if (ok) {
    return res.json({ status: 'promoted', rule_id: ruleId })
  }
  return res.status(404).json({ error: `Rule ${ruleId} not found` })
})

app.post('/api/v1/rules/revoke/:id', (req, res) => {
  const ruleId = parseInt(req.params.id, 10)
  if (isNaN(ruleId)) {
    return res.status(400).json({ error: 'Invalid rule_id' })
  }
  const ok = revokeRule(ruleId, 'manual')
  if (ok) {
    return res.json({ status: 'revoked', rule_id: ruleId })
  }
  return res.status(404).json({ error: `Rule ${ruleId} not found` })
})

// 보관된 룰 목록 조회 — "왜/언제 폐기됐는지" 가시화 (보관/삭제 기준 추적용)
app.get('/api/v1/rules/archived', (_req, res) => {
  const archived = []
  for (const [ruleId, info] of archivedRules) {
    archived.push({
      id: String(ruleId),
      reason: info.reason,
      archived_at: new Date(info.archivedAt).toISOString(),
    })
  }
  return res.json({ archived, total: archived.length })
})

// 재무장(re-arm) — 보관된 룰을 LLM 재생성 없이 shadow 로 되살려 재검증한다.
// 같은 공격이 다시 들어왔을 때 활용. deny 였더라도 다시 shadow(pass,log)로 강등해 검증부터.
app.post('/api/v1/rules/rearm/:id', (req, res) => {
  const ruleId = parseInt(req.params.id, 10)
  if (isNaN(ruleId)) {
    return res.status(400).json({ error: 'Invalid rule_id' })
  }
  const archived = archivedRules.get(ruleId)
  if (!archived) {
    return res.status(404).json({ error: `Rule ${ruleId} not in archive` })
  }
  if (shadowRules.has(ruleId) || liveRules.has(ruleId)) {
    return res.status(409).json({ error: `Rule ${ruleId} already active` })
  }

  // 보관본의 룰 본문(첫 줄)을 shadow 형태로 되돌림
  const shadowRule = normalizeRuleActions(
    archived.ruleText
      .split('\n')[0]
      .replace(/\bdeny,status:\d+/, 'pass,log,auditlog')
      .replace(/\bdeny\b/, 'pass,log,auditlog'),
  )

  try {
    fs.appendFileSync(rulePath, shadowRule + '\n')
  } catch (err) {
    console.error('[Re-arm] rule write failed:', err.message)
    return res
      .status(500)
      .json({ error: 'Rule write failed', detail: err.message })
  }

  shadowRules.set(ruleId, {
    startedAt: Date.now(),
    ruleText: shadowRule,
    expiresAt: Date.now() + TTL_SECONDS * 1000,
  })
  shadowStats.set(ruleId, { total: 0, attack: 0, fp: 0 })
  archivedRules.delete(ruleId)
  console.log(
    `[Re-arm] ${ruleId} restored from archive (was ${archived.reason}) → shadow`,
  )

  scheduleReload()
  return res.json({ status: 'rearmed_shadow', rule_id: ruleId, reload: 'queued' })
})

// ============================================================
// [추가] 룰 목록 조회 - 슬랙 "룰목록" 명령용
//
// dynamic.conf 파일을 한 줄씩 읽으면서, 각 줄에서 Coraza ModSecurity 룰 ID(id:NNNNN)를
// 정규표현식으로 뽑아 반환. 빈 줄과 주석(#) 줄은 건너뜀.
// 본인 요구대로 단순한 형태 (id + 룰 본문)만 반환. Shadow/Live 상태는 표시하지 않음.
// ============================================================
app.get('/api/v1/rules', (_req, res) => {
  let content
  try {
    content = fs.readFileSync(rulePath, 'utf8')
  } catch (err) {
    // 파일이 아직 없으면 빈 목록 반환 (에러 아님)
    if (err.code === 'ENOENT') {
      return res.json({ rules: [], total: 0 })
    }
    console.error('[Sidecar] rule read failed:', err.message)
    return res
      .status(500)
      .json({ error: 'Rule read failed', detail: err.message })
  }

  const lines = content.split('\n')
  const rules = []
  const now = Date.now()

  lines.forEach((line, index) => {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) return

    const match = trimmed.match(/id:(\d+)/)
    if (!match) return

    // dynamic.conf 엔 룰 텍스트만 있고 만료시각이 없으므로 메모리(shadow/live)와 교차 조회
    const meta = describeRuleLifecycle(parseInt(match[1], 10), now)

    rules.push({
      id: match[1],
      line_number: index + 1,
      rule: trimmed,
      status: meta.status, // 'shadow' | 'live' | 'unknown'
      expires_at: meta.expires_at, // live 룰의 실제 만료 예정(ISO) 또는 null
      shadow_until: meta.shadow_until, // shadow 룰의 판정 예정 시각(ISO) 또는 null
    })
  })

  return res.json({ rules, total: rules.length })
})

// 메모리(shadowRules/liveRules)에서 룰 수명 메타데이터를 조회한다.
// 사이드카 재시작 시 메모리 상태는 사라지므로(파일 룰은 유지) status='unknown' 이 될 수 있다.
function describeRuleLifecycle(ruleId, now) {
  if (shadowRules.has(ruleId)) {
    const info = shadowRules.get(ruleId)
    return {
      status: 'shadow',
      shadow_until: new Date(
        info.startedAt + SHADOW_DURATION * 1000,
      ).toISOString(),
      expires_at: null,
    }
  }
  if (liveRules.has(ruleId)) {
    const info = liveRules.get(ruleId)
    const idleExpiry = info.lastMatchedAt + TTL_SECONDS * 1000
    // 하이브리드: idle 만료와 절대 상한 중 먼저 오는 시각이 실제 만료 예정
    const effective = Math.min(idleExpiry, info.expiresAt)
    return {
      status: 'live',
      expires_at: new Date(effective).toISOString(),
      shadow_until: null,
    }
  }
  return { status: 'unknown', expires_at: null, shadow_until: null }
}

// ============================================================
// audit log 워치 — Coraza serial(native) 포맷을 '트랜잭션 단위'로 파싱
//
// native 1건: --<id>-A-- (헤더, client IP 포함) ~ --<id>-Z-- (종료) 사이.
// 한 트랜잭션의 매칭 룰 ID 전체 + client IP 를 모아, shadow 룰 매칭을
// C(CRS 교차검증) + B(IP 평판) 하이브리드로 '공격 vs 오탐'으로 분류한다.
// ============================================================
const BOUNDARY_RE = /^--\S+-([A-Z])--/ // --<boundaryId>-A-- 형태

function isAiRuleId(id) {
  return id >= AI_RULE_ID_MIN && id <= AI_RULE_ID_MAX
}
// CRS(9xxxxx)·Aegis 정적 커스텀 등 사람이 검증한 룰 → 교차검증 신뢰 신호
function isCorroboratingRule(id) {
  return !isAiRuleId(id)
}

// part A 경계 라인에서 client IP 추출:
//   --<id>-A-- [ts] <uniqueId> <clientIP> <clientPort> <serverIP> <serverPort>
function parseClientIpFromAHeader(line) {
  const afterTs = line.includes(']') ? line.slice(line.indexOf(']') + 1) : line
  const tokens = afterTs.trim().split(/\s+/)
  const ip = tokens[1] // [uniqueId, clientIP, ...]
  if (ip && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip
  const m = afterTs.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/)
  return m ? m[1] : null
}

async function isIpBlacklisted(ip) {
  if (!ip || !redisReady) return false // fail-open: Redis 없으면 B 생략(=C만)
  try {
    return (await redisClient.exists(`aegis:blacklist:${ip}`)) === 1
  } catch (err) {
    console.warn(`[Shadow] blacklist 조회 실패(${ip}): ${err.message}`)
    return false
  }
}

// shadow 룰 매칭 1건을 공격/오탐으로 분류해 통계 누적
async function classifyShadowMatch(ruleId, crsCorroborated, ip) {
  const stats = shadowStats.get(ruleId)
  if (!stats) return
  stats.total += 1

  // C(CRS 동시매칭) 또는 B(공격자 IP) 중 하나면 '공격 확정'
  const ipBad = crsCorroborated ? false : await isIpBlacklisted(ip)
  if (crsCorroborated || ipBad) {
    stats.attack += 1
    console.log(
      `[Shadow] ${ruleId} 공격 매칭 (CRS=${crsCorroborated}, ipBlacklist=${ipBad}, ip=${ip}) attack=${stats.attack}`,
    )
  } else {
    stats.fp += 1
    console.log(
      `[Shadow] ${ruleId} 오탐 의심 매칭 (CRS無 + 정상 IP=${ip}) fp=${stats.fp}`,
    )
  }
}

// Coraza 가 차단한 트랜잭션을 Redis 큐로 적재 → worker 가 MongoDB(traffic_logs)에 저장.
// proxy 를 거치지 않고 엣지에서 끊긴 SQLi/XSS 등이 대시보드에 보이게 하는 경로.
async function maybePushBlockedEvent(txn, ids) {
  try {
    // 차단 신호룰(949110 등)이 매칭됐을 때만 = 실제 deny 된 요청
    const blocked = ids.some((id) => BLOCK_SIGNAL_RULE_IDS.includes(id))
    if (!blocked) return
    if (!redisReady) {
      console.warn('[WAFLog] Redis 미연결 — 차단 이벤트 적재 skip')
      return
    }

    // host→tenant 매핑 조회 (proxy 가 Redis aegis:routes 에 발행).
    // 매핑되면 고객사 대시보드(tenant 필터)에도 차단 로그가 보인다.
    let tenantId = null
    let companyName = null
    const host = txn.host ? txn.host.split(':')[0].toLowerCase() : null
    if (host) {
      try {
        const raw = await redisClient.hGet('aegis:routes', host)
        if (raw) {
          const m = JSON.parse(raw)
          tenantId = m.tenant_id || null
          companyName = m.company_name || null
        }
      } catch (err) {
        console.warn(`[WAFLog] route 조회 실패(${host}): ${err.message}`)
      }
    }

    const eventId = `waf-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
    const event = {
      event_id: eventId,
      trace_id: `trace-${eventId}`,
      timestamp: new Date().toISOString(),
      event_type: 'waf_blocked',
      analysis_profile: 'full',
      tenant_id: tenantId, // 매핑 실패 시 null → admin 뷰에만 표시
      company_name: companyName,
      ip: txn.ip || 'unknown',
      session_id: 'unknown',
      method: txn.method || 'GET',
      host: txn.host || null,
      path: txn.path || '/',
      query: txn.query || '',
      headers: {},
      body: '',
      status_code: 403,
      action_on_match: 'block',
      waf_rule_hits: ids, // 매칭된 CRS 룰 ID 전체 (참고용)
    }

    await redisClient.lPush(SECURITY_EVENT_QUEUE, JSON.stringify(event))
    console.log(
      `[WAFLog] 차단 이벤트 적재: ${event.method} ${event.path} from ${event.ip} tenant=${tenantId || '(none)'} (rules=${ids.join(',')})`,
    )
  } catch (err) {
    console.error('[WAFLog] 차단 이벤트 처리 실패:', err.message)
  }
}

// 트랜잭션 종료 시: 라이브 룰 TTL 갱신 + shadow 룰 분류 + 차단 이벤트 적재
function finalizeTransaction(txn) {
  const ids = [...txn.ruleIds]
  if (ids.length === 0) return

  const now = Date.now()
  for (const id of ids) {
    if (liveRules.has(id)) {
      liveRules.get(id).lastMatchedAt = now
      console.log(`[TTL] refreshed ${id}`)
    }
  }

  const crsCorroborated = ids.some(isCorroboratingRule)
  for (const id of ids) {
    if (shadowRules.has(id)) {
      classifyShadowMatch(id, crsCorroborated, txn.ip)
    }
  }

  // Coraza 차단 요청을 MongoDB 파이프라인으로 흘려보냄
  maybePushBlockedEvent(txn, ids)
}

function startLogWatcher() {
  console.log(`[LogWatch] starting tail on ${AUDIT_LOG_PATH}`)

  const tail = new Tail(AUDIT_LOG_PATH, {
    fromBeginning: false, // 기존 로그는 무시, 새 라인만 읽음
    follow: true,
    useWatchFile: true, // Docker 볼륨 호환성 위해
  })

  let txn = null // 현재 누적 중인 트랜잭션
  let captureIp = false // A 파트 IP가 다음 줄에 있는 포맷 대비
  let partB = false // 현재 B(요청 헤더) 파트 안인지
  let expectReqLine = false // B 파트 첫 줄(요청라인) 대기

  tail.on('line', (line) => {
    const b = line.match(BOUNDARY_RE)
    if (b) {
      const part = b[1]
      if (part === 'A') {
        // Coraza native 는 IP 헤더가 보통 '다음 줄'(--id-A-- 단독 줄)이지만,
        // 일부 ModSecurity 호환 출력은 같은 줄에 둔다 → 둘 다 처리.
        const ip = parseClientIpFromAHeader(line)
        txn = { ip, ruleIds: new Set(), method: null, path: null, query: '', host: null }
        captureIp = ip === null // 같은 줄에 없으면 다음 줄에서 캡처
        partB = false
        expectReqLine = false
      } else if (part === 'Z') {
        if (txn) finalizeTransaction(txn)
        txn = null
        captureIp = false
        partB = false
        expectReqLine = false
      } else {
        captureIp = false // 다른 파트 경계 → A 헤더 구간 종료
        partB = part === 'B' // B 파트(요청 헤더) 진입 여부
        expectReqLine = part === 'B' // B 첫 줄 = 요청라인
      }
      return // 경계 라인 자체엔 룰 ID 없음
    }

    if (!txn) {
      // 트랜잭션 경계 밖(파싱 실패 안전망): 라이브 룰 TTL 갱신만
      for (const m of line.matchAll(/\[id "(\d+)"\]/g)) {
        const id = parseInt(m[1], 10)
        if (liveRules.has(id)) liveRules.get(id).lastMatchedAt = Date.now()
      }
      return
    }

    // A 경계 다음 줄에서 client IP 캡처
    if (captureIp && !txn.ip) {
      txn.ip = parseClientIpFromAHeader(line)
      captureIp = false
    }

    // B(요청) 파트: 요청라인(METHOD URI HTTP/x)과 Host 헤더 캡처 → 차단 로그용
    if (partB) {
      if (expectReqLine && line.trim()) {
        const rl = line.trim().match(/^([A-Z]+)\s+(\S+)\s+HTTP\//)
        if (rl) {
          txn.method = rl[1]
          const uri = rl[2]
          const qi = uri.indexOf('?')
          txn.path = qi >= 0 ? uri.slice(0, qi) : uri
          txn.query = qi >= 0 ? uri.slice(qi + 1) : ''
        }
        expectReqLine = false
      } else if (/^Host:\s*/i.test(line)) {
        txn.host = line.replace(/^Host:\s*/i, '').trim()
      }
    }

    // 이 트랜잭션에서 매칭된 모든 룰 ID 누적 (주로 H 파트)
    for (const m of line.matchAll(/\[id "(\d+)"\]/g)) {
      txn.ruleIds.add(parseInt(m[1], 10))
    }
  })

  tail.on('error', (err) => {
    console.error('[LogWatch] error:', err.message)
  })
}

startLogWatcher()
console.log(`[Scheduler] shadow expiration check every 10s`)
console.log(
  `[Scheduler] shadow: duration=${SHADOW_DURATION}s, min_samples=${MIN_SHADOW_SAMPLES}, max_duration=${SHADOW_MAX_DURATION}s`,
)
console.log(
  `[Scheduler] TTL cleanup every ${CLEANUP_INTERVAL}s, idle TTL=${TTL_SECONDS}s, max age=${MAX_RULE_AGE_SECONDS}s`,
)
console.log(`[Sidecar] revoke=보관(archive) 모드, archive_file=${RULE_ARCHIVE_FILE}`)
if (SHADOW_MAX_DURATION < SHADOW_DURATION) {
  console.warn(
    `[Sidecar] 경고: SHADOW_MAX_DURATION(${SHADOW_MAX_DURATION}s) < SHADOW_DURATION(${SHADOW_DURATION}s) → 관찰 연장이 동작하지 않음`,
  )
}

// ============================================================
// 5분 만료 체크 — Shadow 끝난 룰 판정
// ============================================================
function checkShadowExpirations() {
  const now = Date.now()
  const decided = [] // 판정 끝나 shadow 상태에서 내릴 룰들

  for (const [ruleId, info] of shadowRules) {
    const elapsed = now - info.startedAt
    if (elapsed < SHADOW_DURATION * 1000) continue // 아직 1차 관찰 중

    const stats = shadowStats.get(ruleId) || { total: 0, attack: 0, fp: 0 }

    if (stats.fp > 0) {
      // 정상 트래픽이 한 건이라도 매칭 → 차단 시 오탐 위험 → 보관 (정상 0건 차단 보장)
      console.log(
        `[Shadow] revoking ${ruleId} (오탐 의심 ${stats.fp}건, 공격 ${stats.attack}건) — 정상 트래픽 보호`,
      )
      revokeRule(ruleId, 'false_positive')
      decided.push(ruleId)
    } else if (stats.attack >= MIN_SHADOW_SAMPLES) {
      // 공격 표본 충분 + 오탐 0 → 승격
      console.log(
        `[Shadow] promoting ${ruleId} (공격 ${stats.attack}건 ≥ 최소표본 ${MIN_SHADOW_SAMPLES}, 오탐 0)`,
      )
      promoteRule(ruleId)
      decided.push(ruleId)
    } else if (elapsed < SHADOW_MAX_DURATION * 1000) {
      // 표본 부족(공격 ${stats.attack} < ${MIN_SHADOW_SAMPLES}, 오탐 0):
      // 검증 근거가 모자라므로 승격하지 않고 관찰을 연장한다(절대 상한까지).
      // shadowRules 에서 내리지 않음 → 다음 tick 에 재평가. (반복 로그 방지 위해 무출력)
    } else {
      // 절대 상한까지도 표본 부족 → 끝내 검증 불가 → 보관(미검증 룰 자동 deny 금지).
      // 재공격이 들어오면 /api/v1/rules/rearm 으로 재무장 가능.
      console.log(
        `[Shadow] archiving ${ruleId} (표본 부족: 공격 ${stats.attack}건 < ${MIN_SHADOW_SAMPLES}, ${Math.floor(
          elapsed / 1000,
        )}s 관찰) — 미검증 룰 보류`,
      )
      revokeRule(ruleId, 'undersampled')
      decided.push(ruleId)
    }
  }

  // promote 한 룰은 shadow 잔여 상태 제거(revoke 는 내부에서 이미 정리됨; 중복 delete 무해)
  for (const ruleId of decided) {
    shadowRules.delete(ruleId)
    shadowStats.delete(ruleId)
  }
}

// 10초마다 체크
setInterval(checkShadowExpirations, 10 * 1000)

// ============================================================
// TTL 청소부 — 24시간 동안 매칭 없는 라이브 룰 자동 삭제
// ============================================================
function checkTTLExpirations() {
  const now = Date.now()
  const ttlMs = TTL_SECONDS * 1000
  const toRevoke = []

  for (const [ruleId, info] of liveRules) {
    // 하이브리드: ① idle 만료(무매칭 24h) 또는 ② 절대 상한(주입 후 7일) 둘 중 하나라도 충족
    const idleExpired = now - info.lastMatchedAt >= ttlMs
    const maxAgeExpired = now >= info.expiresAt
    if (idleExpired || maxAgeExpired) {
      toRevoke.push({ ruleId, reason: maxAgeExpired ? 'max_age' : 'idle' })
    }
  }

  for (const { ruleId, reason } of toRevoke) {
    const info = liveRules.get(ruleId)
    if (reason === 'max_age') {
      const ageSec = Math.floor((now - info.promotedAt) / 1000)
      console.log(`[TTL] removing ${ruleId} (max age reached, alive ${ageSec}s)`)
    } else {
      const idleSec = Math.floor((now - info.lastMatchedAt) / 1000)
      console.log(`[TTL] removing ${ruleId} (no match for ${idleSec}s)`)
    }
    // idle 만료/절대 상한 모두 '미사용'이라 보관 → 재공격 시 재무장 가능
    revokeRule(ruleId, reason === 'max_age' ? 'max_age' : 'idle_ttl')
  }
}

setInterval(checkTTLExpirations, CLEANUP_INTERVAL * 1000)

// ============================================================
// nginx reload 코얼레서(batching) — 짧은 시간에 몰린 inject/promote/revoke 의
// 개별 reload 를 1회로 합친다. 특히 TTL 청소가 한 tick 에 여러 룰을 내릴 때
// reload N회 → 1회로 줄여 reload 폭주를 막는다. 룰 변경 자체(파일+메모리)는
// 즉시 반영되고, nginx 적용(reload)만 지연·합산된다.
// ============================================================
let reloadTimer = null
let reloadPending = false
let reloadInFlight = false

function scheduleReload() {
  reloadPending = true
  armReloadTimer()
}

function armReloadTimer() {
  if (reloadTimer || reloadInFlight) return
  reloadTimer = setTimeout(() => {
    reloadTimer = null
    fireReload()
  }, RELOAD_DEBOUNCE_MS)
}

function fireReload() {
  if (reloadInFlight || !reloadPending) return
  reloadPending = false
  reloadInFlight = true
  exec(`${nginxBin} -s reload`, (err, _stdout, stderr) => {
    reloadInFlight = false
    if (err) {
      // 설정 검증 실패 시 nginx 는 이전 설정을 유지한다. 무한 재시도 루프를 피하기 위해
      // pending 만 세워두고, 다음 룰 변경(scheduleReload) 때 자연히 재시도되게 한다.
      reloadPending = true
      console.error(
        '[Reload] batched reload 실패(이전 설정 유지):',
        stderr || err.message,
      )
      return
    }
    console.log('[Reload] batched reload 적용 완료')
    if (reloadPending) armReloadTimer() // reload 중 도착한 변경 반영
  })
}

function promoteRule(ruleId) {
  try {
    // 파일 전체 읽기
    const lines = fs.readFileSync(rulePath, 'utf8').split('\n')
    let found = false
    const newLines = lines.map((line) => {
      if (line.includes(`id:${ruleId}`)) {
        found = true
        // pass,log,auditlog → deny,status:403,log,auditlog 로 교체
        return normalizeRuleActions(
          line.replace(/\bpass,log,auditlog\b/, 'deny,status:403,log,auditlog'),
        )
      }
      return line
    })

    if (!found) {
      console.error(`[Promote] rule ${ruleId} not found in ${rulePath}`)
      return false
    }

    fs.writeFileSync(rulePath, newLines.join('\n'))

    // liveRules에 등록
    const now = Date.now()
    liveRules.set(ruleId, {
      promotedAt: now,
      lastMatchedAt: now,
      // 절대 만료 상한(하이브리드). idle 만료와 별개로, 이 시각이 지나면 강제 제거.
      expiresAt: now + MAX_RULE_AGE_SECONDS * 1000,
    })

    // nginx reload (배치)
    console.log(`[Promote] ${ruleId} promoted to deny (reload queued)`)
    scheduleReload()
    return true
  } catch (err) {
    console.error(`[Promote] error for ${ruleId}:`, err.message)
    return false
  }
}

// 폐기되는 룰 원문을 보관 파일 + 메모리에 적재한다(물리 삭제 대신 보관).
// reason: 'false_positive' | 'idle_ttl' | 'max_age' | 'undersampled' | 'manual'
function archiveRule(ruleId, ruleText, reason) {
  archivedRules.set(ruleId, { ruleText, reason, archivedAt: Date.now() })
  try {
    const stamp = new Date().toISOString()
    fs.appendFileSync(
      RULE_ARCHIVE_FILE,
      `# archived id=${ruleId} reason=${reason} at=${stamp}\n${ruleText}\n`,
    )
  } catch (err) {
    console.error(`[Archive] write failed for ${ruleId}:`, err.message)
  }
}

// 룰을 활성 룰 파일(dynamic.conf)에서 내린다. 단, 삭제하지 않고 보관(archive)하여
// 재공격 시 재무장(/api/v1/rules/rearm)으로 LLM 재생성 없이 복구할 수 있게 한다.
function revokeRule(ruleId, reason = 'manual') {
  try {
    const lines = fs.readFileSync(rulePath, 'utf8').split('\n')
    const removed = lines.filter((line) => line.includes(`id:${ruleId}`))
    const newLines = lines.filter((line) => !line.includes(`id:${ruleId}`))

    if (newLines.length === lines.length) {
      console.error(
        `[Revoke] rule ${ruleId} not found in ${rulePath}, cleaning memory anyway`,
      )
      shadowRules.delete(ruleId)
      shadowStats.delete(ruleId)
      liveRules.delete(ruleId)
      return false
    }

    // 물리 삭제 대신 보관: 폐기 근거(reason) 추적 + 재공격 시 재무장 가능
    archiveRule(ruleId, removed.join('\n'), reason)

    fs.writeFileSync(rulePath, newLines.join('\n'))

    // 활성 상태에서만 제거 (archivedRules 에는 남겨둠)
    shadowRules.delete(ruleId)
    shadowStats.delete(ruleId)
    liveRules.delete(ruleId)

    console.log(`[Revoke] ${ruleId} archived (reason=${reason}), reload queued`)
    scheduleReload()
    return true
  } catch (err) {
    console.error(`[Revoke] error for ${ruleId}:`, err.message)
    return false
  }
}

app.listen(port, () => {
  console.log(`[Sidecar] listening on :${port}, rule_file=${rulePath}`)
  console.log(
    `[Sidecar] SHADOW_DURATION=${SHADOW_DURATION}s, TTL=${TTL_SECONDS}s, CLEANUP=${CLEANUP_INTERVAL}s`,
  )
  console.log(`[Sidecar] AUDIT_LOG_PATH=${AUDIT_LOG_PATH}`)
})
