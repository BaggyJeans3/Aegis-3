const express = require('express');
const fs = require('fs');
const { exec } = require('child_process');
const path = require('path');
const Tail = require('tail').Tail;

const app = express();
const port = parseInt(process.env.SIDECAR_PORT || '4000', 10);
const SHADOW_DURATION = parseInt(process.env.SHADOW_DURATION || '300', 10);
const TTL_SECONDS = parseInt(process.env.TTL_SECONDS || '86400', 10);
const CLEANUP_INTERVAL = parseInt(process.env.CLEANUP_INTERVAL || '60', 10);
const AUDIT_LOG_PATH = process.env.AUDIT_LOG_PATH || '/var/log/coraza/audit.log';
const rulePath = process.env.RULE_FILE || '/etc/nginx/rules/dynamic.conf';
const nginxBin = process.env.NGINX_BIN || '/usr/sbin/nginx';

// Shadow Mode 중인 룰들
const shadowRules = new Map();    // rule_id → { startedAt, ruleText }
const shadowCounters = new Map(); // rule_id → matched count

// 승격된 라이브 룰들
const liveRules = new Map();      // rule_id → { promotedAt, lastMatchedAt }

// 시작 시 audit log 파일이 없으면 빈 파일로 만들어둠 (Tail 패키지가 에러 안 내게)
try {
  fs.mkdirSync(path.dirname(AUDIT_LOG_PATH), { recursive: true });
  if (!fs.existsSync(AUDIT_LOG_PATH)) {
    fs.writeFileSync(AUDIT_LOG_PATH, '');
  }
} catch (err) {
  console.error('[Sidecar] audit log init failed:', err.message);
}

app.use(express.json({ limit: '256kb' }));

app.get('/health', (_req, res) => res.json({ ok: true, rule_file: rulePath }));

app.post('/api/v1/rules/inject', (req, res) => {
    const newRule = req.body && req.body.rule;
    if (!newRule || typeof newRule !== 'string') {
        return res.status(400).json({ error: 'Missing or invalid "rule" field' });
    }

    // 1. 룰 텍스트에서 rule_id 추출
    const idMatch = newRule.match(/id:(\d+)/);
    if (!idMatch) {
        return res.status(400).json({ error: 'Rule text must contain id:<number>' });
    }
    const ruleId = parseInt(idMatch[1], 10);

    // 이미 등록된 룰 ID면 거부 (중복 방지)
    if (shadowRules.has(ruleId) || liveRules.has(ruleId)) {
        return res.status(409).json({ error: `Rule ${ruleId} already exists` });
    }

    // 2. deny 액션을 pass,log로 강제 변환 (Shadow Mode)
    const shadowRule = newRule
    .replace(/\bdeny\b/, 'pass,log,auditlog')
    .replace(/,status:\d+/, '')
    .replace(/,log,log,/, ',log,');  // 중복 log 정리

    // 3. 룰 파일에 추가
    try {
        fs.appendFileSync(rulePath, shadowRule + '\n');
    } catch (err) {
        console.error('[Sidecar] rule write failed:', err.message);
        return res.status(500).json({ error: 'Rule write failed', detail: err.message });
    }
    console.log(`[Sidecar] rule appended (shadow): id=${ruleId}`);

    // 4. shadowRules에 등록 (이게 핵심)
    shadowRules.set(ruleId, {
        startedAt: Date.now(),
        ruleText: shadowRule,
        expiresAt: Date.now() + TTL_SECONDS * 1000,  // 참고용 메타데이터
    });
    shadowCounters.set(ruleId, 0);
    console.log(`[Shadow] injected ${ruleId} (will judge in ${SHADOW_DURATION}s)`);

    // 5. nginx reload
    exec(`${nginxBin} -s reload`, (err, _stdout, stderr) => {
        if (err) {
            console.error('[Sidecar] nginx reload failed:', stderr || err.message);
            return res.status(500).json({ error: 'Reload failed', detail: stderr || err.message });
        }
        return res.json({ status: 'shadow_injected', rule_id: ruleId });
    });
});

app.post('/api/v1/rules/promote/:id', (req, res) => {
    const ruleId = parseInt(req.params.id, 10);
    if (isNaN(ruleId)) {
        return res.status(400).json({ error: 'Invalid rule_id' });
    }
    const ok = promoteRule(ruleId);
    if (ok) {
        return res.json({ status: 'promoted', rule_id: ruleId });
    }
    return res.status(404).json({ error: `Rule ${ruleId} not found` });
});

app.post('/api/v1/rules/revoke/:id', (req, res) => {
    const ruleId = parseInt(req.params.id, 10);
    if (isNaN(ruleId)) {
        return res.status(400).json({ error: 'Invalid rule_id' });
    }
    const ok = revokeRule(ruleId);
    if (ok) {
        return res.json({ status: 'revoked', rule_id: ruleId });
    }
    return res.status(404).json({ error: `Rule ${ruleId} not found` });
});


// ============================================================
// audit log 워치 — 룰 매칭 이벤트 수집
// ============================================================
function startLogWatcher() {
  console.log(`[LogWatch] starting tail on ${AUDIT_LOG_PATH}`);
  
  const tail = new Tail(AUDIT_LOG_PATH, {
    fromBeginning: false,  // 기존 로그는 무시, 새 라인만 읽음
    follow: true,
    useWatchFile: true,    // Docker 볼륨 호환성 위해
  });

  tail.on('line', (line) => {
    // 한 줄에서 모든 룰 ID 추출
    const matches = [...line.matchAll(/\[id "(\d+)"\]/g)];
    if (matches.length === 0) return;

    for (const m of matches) {
      const ruleId = parseInt(m[1], 10);
      
      // Shadow 중인 룰이면 카운트
      if (shadowRules.has(ruleId)) {
        const prev = shadowCounters.get(ruleId) || 0;
        shadowCounters.set(ruleId, prev + 1);
        console.log(`[Shadow] matched ${ruleId}, count=${prev + 1}`);
      }
      
      // 라이브 룰이면 last_matched_at 갱신
      if (liveRules.has(ruleId)) {
        const rule = liveRules.get(ruleId);
        rule.lastMatchedAt = Date.now();
        console.log(`[TTL] refreshed ${ruleId}`);
      }
    }
  });

  tail.on('error', (err) => {
    console.error('[LogWatch] error:', err.message);
  });
}

startLogWatcher();
console.log(`[Scheduler] shadow expiration check every 10s`);
console.log(`[Scheduler] TTL cleanup every ${CLEANUP_INTERVAL}s, TTL=${TTL_SECONDS}s`);

// ============================================================
// 5분 만료 체크 — Shadow 끝난 룰 판정
// ============================================================
function checkShadowExpirations() {
    const now = Date.now();
    const expired = [];

    for (const [ruleId, info] of shadowRules) {
        if (now - info.startedAt >= SHADOW_DURATION * 1000) {
            expired.push(ruleId);
        }
    }

    for (const ruleId of expired) {
        const count = shadowCounters.get(ruleId) || 0;
        if (count === 0) {
            console.log(`[Shadow] promoting ${ruleId} (FP=0)`);
            promoteRule(ruleId);
        } else {
            console.log(`[Shadow] revoking ${ruleId} (FP=${count})`);
            revokeRule(ruleId);
        }
        shadowRules.delete(ruleId);
        shadowCounters.delete(ruleId);
    }
}

// 10초마다 체크
setInterval(checkShadowExpirations, 10 * 1000);

// ============================================================
// TTL 청소부 — 24시간 동안 매칭 없는 라이브 룰 자동 삭제
// ============================================================
function checkTTLExpirations() {
    const now = Date.now();
    const ttlMs = TTL_SECONDS * 1000;
    const toRevoke = [];

    for (const [ruleId, info] of liveRules) {
        if (now - info.lastMatchedAt >= ttlMs) {
            toRevoke.push(ruleId);
        }
    }

    for (const ruleId of toRevoke) {
        const idleSec = Math.floor((now - liveRules.get(ruleId).lastMatchedAt) / 1000);
        console.log(`[TTL] removing ${ruleId} (no match for ${idleSec}s)`);
        revokeRule(ruleId);  // revokeRule이 liveRules.delete까지 다 처리함
    }
}

setInterval(checkTTLExpirations, CLEANUP_INTERVAL * 1000);

function promoteRule(ruleId) {
    try {
        // 파일 전체 읽기
        const lines = fs.readFileSync(rulePath, 'utf8').split('\n');
        let found = false;
        const newLines = lines.map(line => {
            if (line.includes(`id:${ruleId}`)) {
                found = true;
                // pass,log,auditlog → deny,status:403,log,auditlog 로 교체
                return line.replace(/\bpass,log,auditlog\b/, 'deny,status:403,log,auditlog');
            }
            return line;
        });

        if (!found) {
            console.error(`[Promote] rule ${ruleId} not found in ${rulePath}`);
            return false;
        }

        fs.writeFileSync(rulePath, newLines.join('\n'));
        
        // liveRules에 등록
        const now = Date.now();
        liveRules.set(ruleId, {
            promotedAt: now,
            lastMatchedAt: now,
            expiresAt: now + TTL_SECONDS * 1000,
        });

        // nginx reload
        exec(`${nginxBin} -s reload`, (err) => {
            if (err) {
                console.error(`[Promote] reload failed for ${ruleId}:`, err.message);
            } else {
                console.log(`[Promote] ${ruleId} promoted to deny + reloaded`);
            }
        });
        return true;
    } catch (err) {
        console.error(`[Promote] error for ${ruleId}:`, err.message);
        return false;
    }
}

function revokeRule(ruleId) {
    try {
        const lines = fs.readFileSync(rulePath, 'utf8').split('\n');
        const newLines = lines.filter(line => !line.includes(`id:${ruleId}`));

        if (newLines.length === lines.length) {
            console.error(`[Revoke] rule ${ruleId} not found in ${rulePath}, cleaning memory anyway`);
            shadowRules.delete(ruleId);
            shadowCounters.delete(ruleId);
            liveRules.delete(ruleId);
            return false;
        }

        fs.writeFileSync(rulePath, newLines.join('\n'));

        // 모든 상태에서 제거
        shadowRules.delete(ruleId);
        shadowCounters.delete(ruleId);
        liveRules.delete(ruleId);

        exec(`${nginxBin} -s reload`, (err) => {
            if (err) {
                console.error(`[Revoke] reload failed for ${ruleId}:`, err.message);
            } else {
                console.log(`[Revoke] ${ruleId} removed + reloaded`);
            }
        });
        return true;
    } catch (err) {
        console.error(`[Revoke] error for ${ruleId}:`, err.message);
        return false;
    }
}

app.listen(port, () => {
  console.log(`[Sidecar] listening on :${port}, rule_file=${rulePath}`);
  console.log(`[Sidecar] SHADOW_DURATION=${SHADOW_DURATION}s, TTL=${TTL_SECONDS}s, CLEANUP=${CLEANUP_INTERVAL}s`);
  console.log(`[Sidecar] AUDIT_LOG_PATH=${AUDIT_LOG_PATH}`);
});