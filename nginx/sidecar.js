const express = require('express');
const fs = require('fs');
const { exec } = require('child_process');

const app = express();
const port = parseInt(process.env.SIDECAR_PORT || '4000', 10);
const rulePath = process.env.RULE_FILE || '/etc/nginx/rules/dynamic.conf';
const nginxBin = process.env.NGINX_BIN || '/usr/sbin/nginx';

app.use(express.json({ limit: '256kb' }));

app.get('/health', (_req, res) => res.json({ ok: true, rule_file: rulePath }));

app.post('/api/v1/rules/inject', (req, res) => {
    const newRule = req.body && req.body.rule;
    if (!newRule || typeof newRule !== 'string') {
        return res.status(400).json({ error: 'Missing or invalid "rule" field' });
    }

    try {
        fs.appendFileSync(rulePath, newRule + '\n');
    } catch (err) {
        console.error('[Sidecar] rule write failed:', err.message);
        return res.status(500).json({ error: 'Rule write failed', detail: err.message });
    }
    console.log(`[Sidecar] rule appended: ${newRule}`);

    exec(`${nginxBin} -s reload`, (err, _stdout, stderr) => {
        if (err) {
            console.error('[Sidecar] nginx reload failed:', stderr || err.message);
            return res.status(500).json({ error: 'Reload failed', detail: stderr || err.message });
        }
        return res.json({ status: 'reloaded' });
    });
});

app.listen(port, () => {
    console.log(`[Sidecar] listening on :${port}, rule_file=${rulePath}`);
});