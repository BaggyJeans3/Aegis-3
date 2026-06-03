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

// AI 동적 룰 ID 대역 (README 기준). 이 밖의 매칭 룰(CRS 9xxxxx·정적 커스텀)은
// 사람이 검증한 룰이라 Shadow 판정의 교차검증(C) 신호로 신뢰한다.
const AI_RULE_ID_MIN = 2000000000
const AI_RULE_ID_MAX = 2099999999

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

// 시작 시 audit log 파일이 없으면 빈 파일로 만들어둠 (Tail 패키지가 에러 안 내게)
try {
  fs.mkdirSync(path.dirname(AUDIT_LOG_PATH), { recursive: true })
  if (!fs.existsSync(AUDIT_LOG_PATH)) {
    fs.writeFileSync(AUDIT_LOG_PATH, '')
  }
} catch (err) {
  console.error('[Sidecar] audit log init failed:', err.message)
}

app.use(express.json({ limit: '256kb' }))

app.get('/health', (_req, res) => res.json({ ok: true, rule_file: rulePath }))

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

  // 2. deny 액션을 pass,log로 강제 변환 (Shadow Mode)
  const shadowRule = newRule
    .replace(/\bdeny\b/, 'pass,log,auditlog')
    .replace(/,status:\d+/, '')
    .replace(/,log,log,/, ',log,') // 중복 log 정리

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

  // 5. nginx reload
  exec(`${nginxBin} -s reload`, (err, _stdout, stderr) => {
    if (err) {
      console.error('[Sidecar] nginx reload failed:', stderr || err.message)
      return res
        .status(500)
        .json({ error: 'Reload failed', detail: stderr || err.message })
    }
    return res.json({ status: 'shadow_injected', rule_id: ruleId })
  })
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
  const ok = revokeRule(ruleId)
  if (ok) {
    return res.json({ status: 'revoked', rule_id: ruleId })
  }
  return res.status(404).json({ error: `Rule ${ruleId} not found` })
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

// 트랜잭션 종료 시: 라이브 룰 TTL 갱신 + shadow 룰 분류
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
}

function startLogWatcher() {
  console.log(`[LogWatch] starting tail on ${AUDIT_LOG_PATH}`)

  const tail = new Tail(AUDIT_LOG_PATH, {
    fromBeginning: false, // 기존 로그는 무시, 새 라인만 읽음
    follow: true,
    useWatchFile: true, // Docker 볼륨 호환성 위해
  })

  let txn = null // 현재 누적 중인 트랜잭션

  tail.on('line', (line) => {
    const b = line.match(BOUNDARY_RE)
    if (b) {
      const part = b[1]
      if (part === 'A') {
        txn = { ip: parseClientIpFromAHeader(line), ruleIds: new Set() }
      } else if (part === 'Z') {
        if (txn) finalizeTransaction(txn)
        txn = null
      }
    }

    if (txn) {
      // 이 트랜잭션에서 매칭된 모든 룰 ID 누적 (주로 H 파트)
      for (const m of line.matchAll(/\[id "(\d+)"\]/g)) {
        txn.ruleIds.add(parseInt(m[1], 10))
      }
    } else {
      // 트랜잭션 경계 밖(파싱 실패 안전망): 라이브 룰 TTL 갱신만
      for (const m of line.matchAll(/\[id "(\d+)"\]/g)) {
        const id = parseInt(m[1], 10)
        if (liveRules.has(id)) liveRules.get(id).lastMatchedAt = Date.now()
      }
    }
  })

  tail.on('error', (err) => {
    console.error('[LogWatch] error:', err.message)
  })
}

startLogWatcher()
console.log(`[Scheduler] shadow expiration check every 10s`)
console.log(
  `[Scheduler] TTL cleanup every ${CLEANUP_INTERVAL}s, idle TTL=${TTL_SECONDS}s, max age=${MAX_RULE_AGE_SECONDS}s`,
)

// ============================================================
// 5분 만료 체크 — Shadow 끝난 룰 판정
// ============================================================
function checkShadowExpirations() {
  const now = Date.now()
  const expired = []

  for (const [ruleId, info] of shadowRules) {
    if (now - info.startedAt >= SHADOW_DURATION * 1000) {
      expired.push(ruleId)
    }
  }

  for (const ruleId of expired) {
    const stats = shadowStats.get(ruleId) || { total: 0, attack: 0, fp: 0 }
    if (stats.fp > 0) {
      // 정상 트래픽이 한 건이라도 매칭 → 차단 시 오탐 위험 → 폐기 (정상 0건 차단 보장)
      console.log(
        `[Shadow] revoking ${ruleId} (오탐 의심 ${stats.fp}건, 공격 ${stats.attack}건) — 정상 트래픽 보호`,
      )
      revokeRule(ruleId)
    } else if (stats.attack > 0) {
      // 공격만 매칭, 오탐 0 → 승격
      console.log(
        `[Shadow] promoting ${ruleId} (공격 ${stats.attack}건, 오탐 0)`,
      )
      promoteRule(ruleId)
    } else {
      // 매칭 자체가 없음 → 승격 (FP=0)
      console.log(`[Shadow] promoting ${ruleId} (매칭 없음, FP=0)`)
      promoteRule(ruleId)
    }
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
    revokeRule(ruleId) // revokeRule이 liveRules.delete까지 다 처리함
  }
}

setInterval(checkTTLExpirations, CLEANUP_INTERVAL * 1000)

function promoteRule(ruleId) {
  try {
    // 파일 전체 읽기
    const lines = fs.readFileSync(rulePath, 'utf8').split('\n')
    let found = false
    const newLines = lines.map((line) => {
      if (line.includes(`id:${ruleId}`)) {
        found = true
        // pass,log,auditlog → deny,status:403,log,auditlog 로 교체
        return line.replace(
          /\bpass,log,auditlog\b/,
          'deny,status:403,log,auditlog',
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

    // nginx reload
    exec(`${nginxBin} -s reload`, (err) => {
      if (err) {
        console.error(`[Promote] reload failed for ${ruleId}:`, err.message)
      } else {
        console.log(`[Promote] ${ruleId} promoted to deny + reloaded`)
      }
    })
    return true
  } catch (err) {
    console.error(`[Promote] error for ${ruleId}:`, err.message)
    return false
  }
}

function revokeRule(ruleId) {
  try {
    const lines = fs.readFileSync(rulePath, 'utf8').split('\n')
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

    fs.writeFileSync(rulePath, newLines.join('\n'))

    // 모든 상태에서 제거
    shadowRules.delete(ruleId)
    shadowStats.delete(ruleId)
    liveRules.delete(ruleId)

    exec(`${nginxBin} -s reload`, (err) => {
      if (err) {
        console.error(`[Revoke] reload failed for ${ruleId}:`, err.message)
      } else {
        console.log(`[Revoke] ${ruleId} removed + reloaded`)
      }
    })
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
