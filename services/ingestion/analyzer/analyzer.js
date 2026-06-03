// 1. 환경 변수 로드 (현재 폴더의 .env 파일을 자동으로 읽습니다)
require('dotenv').config()
const axios = require('axios')
const { App } = require('@slack/bolt')
const nodemailer = require('nodemailer')

// --- [환경 설정 확인] ---
const {
  CF_TOKEN,
  ZONE_ID,
  SLACK_BOT_TOKEN,
  SLACK_SIGNING_SECRET,
  EMAIL_USER,
  EMAIL_PASS,
} = process.env

// 사이드카 베이스 URL.
//   - EC2: 사이드카가 nginx 컨테이너 안에서 같이 돌기 때문에 컨테이너 이름은 "nginx"
//          (docker-compose.yml 의 soar-api/soar-worker 가 이미 http://nginx:4000 사용 중)
//   - PC 로컬 테스트: .env 에 SIDECAR_BASE_URL=http://localhost:4000 으로 덮어쓰면 됨
const SIDECAR_BASE_URL = process.env.SIDECAR_BASE_URL || 'http://nginx:4000'

// 2. 슬랙 봇 초기화 (Socket Mode)
//   - HTTP Mode 는 슬랙이 본인 서버로 들어오는 inbound 연결이 필요해서 NAT/방화벽 뒤에선 동작 안 함
//   - Socket Mode 는 봇이 슬랙으로 outbound WebSocket 을 맺어서 PC/EC2 어디서나 동작
const slackApp = new App({
  token: SLACK_BOT_TOKEN,
  signingSecret: SLACK_SIGNING_SECRET,
  socketMode: true,
  appToken: process.env.SLACK_APP_TOKEN,
})

// --- [기능 1: Cloudflare WAF IP 차단] ---
async function blockIpOnCloudflare(targetIp) {
  const url = `https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/firewall/access_rules/rules`
  try {
    await axios.post(
      url,
      {
        mode: 'block',
        configuration: { target: 'ip', value: targetIp },
        notes: 'Aegis 3: 지능형 보안 엔진에 의한 자동 차단',
      },
      {
        headers: {
          Authorization: `Bearer ${CF_TOKEN}`,
          'Content-Type': 'application/json',
        },
      },
    )
    console.log(`✅ [Cloudflare] IP ${targetIp} 차단 성공`)
  } catch (err) {
    console.error(
      '❌ Cloudflare API 에러:',
      err.response ? err.response.data : err.message,
    )
  }
}

// --- [추가: Cloudflare WAF IP 차단 해제] ---
// 1) 해당 IP 의 access_rule 을 검색
// 2) 검색 결과의 rule id 로 DELETE
// 동일 IP 에 룰이 여러 개면 전부 삭제.
async function unblockIpOnCloudflare(targetIp) {
  const baseUrl = `https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/firewall/access_rules/rules`
  const headers = {
    Authorization: `Bearer ${CF_TOKEN}`,
    'Content-Type': 'application/json',
  }

  try {
    const listResp = await axios.get(baseUrl, {
      headers,
      params: {
        'configuration.target': 'ip',
        'configuration.value': targetIp,
        mode: 'block',
      },
    })
    const rules = (listResp.data && listResp.data.result) || []
    if (rules.length === 0) {
      return { ok: false, reason: 'not_found' }
    }

    const deleted = []
    for (const rule of rules) {
      await axios.delete(`${baseUrl}/${rule.id}`, { headers })
      deleted.push(rule.id)
    }
    console.log(
      `✅ [Cloudflare] IP ${targetIp} 차단 해제 (rules: ${deleted.join(', ')})`,
    )
    return { ok: true, deleted }
  } catch (err) {
    const detail = err.response ? err.response.data : err.message
    console.error('❌ Cloudflare unblock 에러:', detail)
    return { ok: false, reason: 'api_error', detail }
  }
}

// --- [기능 2: 이메일 보안 보고서 전송] ---
async function sendSecurityEmail(ip, attackType) {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: EMAIL_USER, pass: EMAIL_PASS },
  })

  try {
    await transporter.sendMail({
      from: `"Aegis-3" <${EMAIL_USER}>`,
      to: 'baggyjeans2026@gmail.com',
      subject: `🚨 [긴급] 보안 위협 대응 리포트 (${ip})`,
      html: `
                <div style="font-family: sans-serif; border: 1px solid #d9d9d9; padding: 20px;">
                    <h2 style="color: #d32f2f;">보안 위협 감지 및 즉각 조치 보고</h2>
                    <hr>
                    <p><b>탐지 대상 IP:</b> ${ip}</p>
                    <p><b>공격 유형:</b> ${attackType}</p>
                    <p><b>조치 내역:</b> Cloudflare WAF 블랙리스트 등록 및 내부망 룰 주입 완료</p>
                    <br>
                    <p style="color: #757575;">본 메일은 Aegis 3 시스템에 의해 자동 발송되었습니다.</p>
                </div>
            `,
    })
    console.log('📧 이메일 보고서 발송 성공')
  } catch (err) {
    console.error('❌ 이메일 발송 에러:', err.message)
  }
}

// --- [기능 3: 슬랙 알림] ---
async function notifySlack(ip, attackType) {
  try {
    await slackApp.client.chat.postMessage({
      channel: 'security-alerts',
      text: `🚨 *이지스 3 공격 차단 알림*`,
      attachments: [
        {
          color: '#ff0000',
          fields: [
            { title: '공격 IP', value: ip, short: true },
            { title: '공격 유형', value: attackType, short: true },
            { title: '조치 상태', value: 'CF WAF 차단 완료', short: false },
          ],
        },
      ],
    })
    console.log('💬 슬랙 알림 전송 성공')
  } catch (err) {
    console.error('❌ 슬랙 전송 에러:', err.message)
  }
}

// --- [이지스 3 통합 보고 창구] ---
const { createServer } = require('http')
const express = require('express')
const app = express()
app.use(express.json())

app.post('/api/v1/report', async (req, res) => {
  const { ip, type } = req.body
  console.log(`🚨 [Aegis-3 시스템] 공격 보고 수신: ${ip} (${type})`)
  await aegisResponse(ip, type)
  res
    .status(200)
    .send({ status: 'Success', detail: '대응 절차(CF/Slack/Email) 시작됨' })
})

app.listen(5000, () =>
  console.log('🚀 Aegis-3 리포트 수신 서버 가동 (Port 5000)'),
)

// ============================================================
// [추가] 슬랙 대화형 명령어 - 차단해제 / 룰목록 / 룰비활성
// ============================================================

// 명령어 1: 차단해제 <IP>
// 예시: "차단해제 1.2.3.4"
slackApp.message(/^차단해제\s+(\S+)/, async ({ context, say, message }) => {
  const ip = context.matches[1]

  // 간단한 IPv4 형식 검증 (악의적/오입력으로 Cloudflare 호출하는 것 방지)
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    await say(`❌ IP 형식이 올바르지 않습니다: \`${ip}\``)
    return
  }

  await say(
    `🔍 <@${message.user}>님 요청으로 \`${ip}\` Cloudflare 차단 해제 시도 중...`,
  )

  const result = await unblockIpOnCloudflare(ip)

  if (result.ok) {
    await say(
      `✅ \`${ip}\` Cloudflare 차단 해제 완료 (삭제된 rule id: ${result.deleted.join(', ')})`,
    )
  } else if (result.reason === 'not_found') {
    await say(`⚠️ \`${ip}\`에 대한 활성 차단 룰을 찾지 못했습니다.`)
  } else {
    await say(
      `❌ 차단 해제 실패: ${typeof result.detail === 'string' ? result.detail : JSON.stringify(result.detail)}`,
    )
  }
})

// 명령어 2: 룰목록
// 예시: "룰목록"
// 사이드카의 GET /api/v1/rules 호출 -> 현재 dynamic.conf 에 있는 룰의 ID 와 본문 반환
// (Shadow/Live 상태 구분은 안 함 - 단순한 형태)
slackApp.message(/^룰목록\s*$/, async ({ say, message }) => {
  await say(
    `🔍 <@${message.user}>님 요청으로 현재 주입된 AI 룰 목록 조회 중...`,
  )

  try {
    const resp = await axios.get(`${SIDECAR_BASE_URL}/api/v1/rules`, {
      timeout: 5000,
    })
    const rules = (resp.data && resp.data.rules) || []

    if (rules.length === 0) {
      await say(`📭 현재 주입된 동적 룰이 없습니다.`)
      return
    }

    // 슬랙 메시지는 너무 길면 잘리므로 최대 20개까지만 표시.
    // 룰 본문도 길면 100자로 자름 (가독성).
    const shown = rules.slice(0, 20)
    const summary = shown
      .map((r) => {
        const snippet =
          r.rule.length > 100 ? r.rule.slice(0, 97) + '...' : r.rule
        return `• *id:${r.id}*\n   \`${snippet}\``
      })
      .join('\n')

    const more =
      rules.length > shown.length
        ? `\n\n(총 ${rules.length}개 중 ${shown.length}개 표시)`
        : `\n\n총 ${rules.length}개`

    await say(`📋 *현재 주입된 동적 룰 목록*\n${summary}${more}`)
  } catch (err) {
    const detail = err.response
      ? JSON.stringify(err.response.data)
      : err.message
    console.error('❌ 룰목록 조회 실패:', detail)
    await say(`❌ 룰 목록 조회 실패: ${detail}`)
  }
})

// 명령어 3: 룰비활성 <id>
// 예시: "룰비활성 99999"
// 사이드카의 POST /api/v1/rules/revoke/:id 호출 (팀원 sidecar.js 형식 - URL 파라미터)
// 사이드카의 revokeRule() 함수가 shadowRules / shadowCounters / liveRules 메모리도 같이 정리해줌.
slackApp.message(/^룰비활성\s+(\d+)/, async ({ context, say, message }) => {
  const ruleId = context.matches[1]

  await say(
    `🔍 <@${message.user}>님 요청으로 룰 \`id:${ruleId}\` 비활성 시도 중...`,
  )

  try {
    const resp = await axios.post(
      `${SIDECAR_BASE_URL}/api/v1/rules/revoke/${ruleId}`,
      null, // 본문 없음 (팀원 sidecar 는 URL 파라미터로 받음)
      { timeout: 10000 },
    )
    const data = resp.data || {}
    await say(
      `✅ 룰 \`id:${ruleId}\` 비활성 완료 (status: ${data.status || 'unknown'})`,
    )
  } catch (err) {
    if (err.response && err.response.status === 404) {
      await say(`⚠️ 룰 \`id:${ruleId}\` 을(를) 찾지 못했습니다.`)
      return
    }
    if (err.response && err.response.status === 400) {
      await say(`❌ 잘못된 룰 ID 형식: \`${ruleId}\``)
      return
    }
    const detail = err.response
      ? JSON.stringify(err.response.data)
      : err.message
    console.error('❌ 룰비활성 실패:', detail)
    await say(`❌ 룰 비활성 실패: ${detail}`)
  }
})

// --- 기존: 슬랙 대화형 명령어 (봇에게 '보고'라고 치면 작동) ---
slackApp.message('보고', async ({ message, say }) => {
  await say(
    `확인했습니다, <@${message.user}>님. 현재까지의 탐지 내역을 종합하여 **baegijeans@email.com**으로 즉시 이메일 보고서를 발송합니다.`,
  )
  await sendSecurityEmail('최근 집계 IP', '슬랙 수동 요청 분석')
})

// --- [통합 제어 엔진] ---
async function aegisResponse(ip, type) {
  console.log(`\n🔍 [Aegis-3] 분석 중: ${ip} (${type})`)
  await blockIpOnCloudflare(ip)
  await notifySlack(ip, type)
  await sendSecurityEmail(ip, type)
}

// --- [서버 가동] ---
;(async () => {
  try {
    await slackApp.start(process.env.PORT || 3000)
    console.log('⚡️ Aegis-3 대응 엔진이 정상 가동 중입니다 (Port 3000)')
    console.log(`   사이드카 베이스 URL: ${SIDECAR_BASE_URL}`)
  } catch (error) {
    console.error('❌ 서버 시작 실패:', error)
  }
})()
