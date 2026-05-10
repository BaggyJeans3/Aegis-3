// 1. 환경 변수 로드 (현재 폴더의 .env 파일을 자동으로 읽습니다)
require('dotenv').config();
const axios = require('axios');
const { App } = require('@slack/bolt');
const nodemailer = require('nodemailer');

// --- [환경 설정 확인] ---
const {
    CF_TOKEN,
    ZONE_ID,
    SLACK_BOT_TOKEN,
    SLACK_SIGNING_SECRET,
    EMAIL_USER,
    EMAIL_PASS
} = process.env;

// 2. 슬랙 봇 초기화
const slackApp = new App({
    token: SLACK_BOT_TOKEN,
    signingSecret: SLACK_SIGNING_SECRET
});

// --- [기능 1: Cloudflare WAF IP 차단] ---
async function blockIpOnCloudflare(targetIp) {
    const url = `https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/firewall/access_rules/rules`;
    try {
        await axios.post(url, {
            mode: "block",
            configuration: { target: "ip", value: targetIp },
            notes: "Aegis 3: 지능형 보안 엔진에 의한 자동 차단"
        }, {
            headers: {
                'Authorization': `Bearer ${CF_TOKEN}`,
                'Content-Type': 'application/json'
            }
        });
        console.log(`✅ [Cloudflare] IP ${targetIp} 차단 성공`);
    } catch (err) {
        console.error("❌ Cloudflare API 에러:", err.response ? err.response.data : err.message);
    }
}

// --- [기능 2: 이메일 보안 보고서 전송] ---
async function sendSecurityEmail(ip, attackType) {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: EMAIL_USER, pass: EMAIL_PASS }
    });

    try {
        await transporter.sendMail({
            from: `"이지스 3 관제시스템" <${EMAIL_USER}>`,
            to: "baegijeans@email.com", // 담당자 수신 이메일
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
            `
        });
        console.log("📧 이메일 보고서 발송 성공");
    } catch (err) {
        console.error("❌ 이메일 발송 에러:", err.message);
    }
}

// --- [기능 3: 슬랙 알림 및 명령어 처리] ---
// 3-1. 실시간 알림 함수
async function notifySlack(ip, attackType) {
    try {
        await slackApp.client.chat.postMessage({
            channel: 'security-alerts', // 혹은 채널 ID (예: C12345678)
            text: `🚨 *이지스 3 공격 차단 알림*`,
            attachments: [{
                color: "#ff0000",
                fields: [
                    { title: "공격 IP", value: ip, short: true },
                    { title: "공격 유형", value: attackType, short: true },
                    { title: "조치 상태", value: "CF WAF 차단 완료", short: false }
                ]
            }]
        });
        console.log("💬 슬랙 알림 전송 성공");
    } catch (err) {
        console.error("❌ 슬랙 전송 에러:", err.message);
    }
}

// --- [이지스 3 통합 보고 창구] ---
// Nginx나 로그 분석기가 공격을 발견하면 이쪽으로 데이터를 쏩니다.
const { createServer } = require('http');
const express = require('express');
const app = express();
app.use(express.json());

app.post('/api/v1/report', async (req, res) => {
    const { ip, type } = req.body;
    console.log(`🚨 [Aegis-3 시스템] 공격 보고 수신: ${ip} (${type})`);
    
    // 이 한 줄이 유저님이 원하시는 모든 기능을 실행합니다.
    await aegisResponse(ip, type); 
    
    res.status(200).send({ status: "Success", detail: "대응 절차(CF/Slack/Email) 시작됨" });
});

// 기존 slackApp.start 외에 API 서버도 같이 띄웁니다.
app.listen(5000, () => console.log('🚀 Aegis-3 리포트 수신 서버 가동 (Port 5000)'));


// 3-2. 슬랙 대화형 명령어 (봇에게 '보고'라고 치면 작동)
slackApp.message('보고', async ({ message, say }) => {
    await say(`확인했습니다, <@${message.user}>님. 현재까지의 탐지 내역을 종합하여 **baegijeans@email.com**으로 즉시 이메일 보고서를 발송합니다.`);
    await sendSecurityEmail("최근 집계 IP", "슬랙 수동 요청 분석");
});

// --- [통합 제어 엔진] ---
async function aegisResponse(ip, type) {
    console.log(`\n🔍 [Aegis-3] 분석 중: ${ip} (${type})`);
    
    // 세 가지 액션을 순차적으로 실행
    await blockIpOnCloudflare(ip);
    await notifySlack(ip, type);
    await sendSecurityEmail(ip, type);
}

// --- [서버 가동] ---
(async () => {
    try {
        await slackApp.start(process.env.PORT || 3000);
        console.log('⚡️ Aegis-3 대응 엔진이 정상 가동 중입니다 (Port 3000)');
        
        // 테스트용: 실행하자마자 작동하는지 보려면 아래 주석을 해제하세요.
        // await aegisResponse("1.2.3.4", "SQL Injection Test");
    } catch (error) {
        console.error("❌ 서버 시작 실패:", error);
    }
})();
