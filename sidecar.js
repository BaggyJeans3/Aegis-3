const express = require('express');
const fs = require('fs');
const { exec } = require('child_process');
const app = express();
const port = 4000; // 내부망 통신 포트

app.use(express.json());

// 분석 서버(Node-2)로부터 룰을 받는 엔드포인트
app.post('/api/v1/rules/inject', (req, res) => {
    const newRule = req.body.rule; 
    const rulePath = '/etc/nginx/rules/dynamic.conf';

    // 1. dynamic.conf 파일에 새로운 룰 추가
    fs.appendFileSync(rulePath, newRule + '\n');
    console.log(`[내부망] 새로운 룰 주입 완료: ${newRule}`);

    // 2. Nginx 설정 적용 (Reload)
    // /usr/local/nginx/sbin/nginx 경로는 이전 빌드 설정 기준입니다.
    exec('sudo /usr/local/nginx/sbin/nginx -s reload', (err) => {
        if (err) {
            console.error("Nginx 리로드 실패:", err);
            return res.status(500).send("Reload Failed");
        }
        res.send("Rule Injected & Nginx Reloaded");
    });
});

app.listen(port, () => {
    console.log(`Aegis-3 Sidecar API가 ${port}번 포트에서 가동 중입니다.`);
});
