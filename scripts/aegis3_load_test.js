/**
 * Aegis-3 부하 테스트 스크립트 (k6)
 * =====================================
 * Nginx + Coraza WAF → Node.js Proxy → 고객사 서버 전체 경로 대상.
 *
 * 시나리오는 환경변수로 선택:
 *   SCENARIO=normal   정상 트래픽 부하 (RPS / 응답시간 측정)
 *   SCENARIO=attack   공격 트래픽 부하 (Coraza 403 처리 안정성)
 *   SCENARIO=mixed    혼합 트래픽 (정상 80% + 공격 20%)
 *   SCENARIO=soak     장시간 안정성 (메모리 누수 점검)
 *
 * 실행 예:
 *   k6 run -e TARGET=http://localhost -e SCENARIO=normal aegis3_load_test.js
 *
 * [SOAR 주의 — 실행 전 확인]
 *   - soar-worker 의 AI_RULE_THRESHOLD 가 운영값(80)인지 확인할 것. 시연값(30, demo_setup.sh)이면
 *     단일 IP 요청량 룰(R-RATE-001 = 30점)만으로 수 초 내 SOAR 대응이 트리거되어
 *     k6 IP 블랙리스트(이후 proxy 403) + Cloudflare 차단 + Slack/Email 이 이벤트마다 발송된다.
 *       확인: sudo docker exec aegis-soar-worker printenv AI_RULE_THRESHOLD
 *   - 기본 실행은 모든 VU 가 같은 IP → 정상 트래픽도 R-RATE-002(50점, HIGH)로 대시보드에 찍힌다(정상 동작).
 *     '다수의 정상 사용자' 부하를 재려면 -e SPREAD_IPS=1024 로 정상 요청의 X-Forwarded-For 를 분산한다.
 *     (벤치마크 전용 대역 198.18.0.0/15 사용)
 *   - SOAR 쪽 사전 점검: python3 scripts/soar_bench/k6_threshold_sim.py [--spread-ips 1024]
 *
 * Docker로 실행 (k6 설치 불필요):
 *   docker run --rm -i --network host \
 *     -e TARGET=http://localhost -e SCENARIO=normal \
 *     -v $(pwd):/scripts grafana/k6 run /scripts/aegis3_load_test.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Trend, Rate } from 'k6/metrics';

// ---------------------------------------------------------
// 설정
// ---------------------------------------------------------
const TARGET = __ENV.TARGET || 'http://localhost';
const SCENARIO = __ENV.SCENARIO || 'normal';
// 0 이면 기존 동작(단일 IP). N>0 이면 정상 요청에 X-Forwarded-For: 198.18.x.y (N개 중 하나) 부여
const SPREAD_IPS = parseInt(__ENV.SPREAD_IPS || '0', 10);

function spreadIp() {
  const n = Math.floor(Math.random() * SPREAD_IPS);
  return `198.18.${Math.floor(n / 256)}.${n % 256}`;
}

// http_req_failed 기준: k6 기본값은 4xx 전부 실패 → WAF 가 공격을 403 으로 막을수록 실패율이 올라
// attack/mixed 가 항상 불합격이었다. WAF 차단(401/403)은 '정상 응답'으로 본다.
// 429(rate limit)는 정상 사용자가 막힌 것이므로 계속 실패로 센다.
http.setResponseCallback(http.expectedStatuses({ min: 200, max: 399 }, 401, 403));

// 커스텀 메트릭
const blockedRequests = new Counter('aegis_blocked_requests');   // 403 차단 수
const passedRequests = new Counter('aegis_passed_requests');     // 200 통과 수
const rateLimited = new Counter('aegis_rate_limited');           // 429 (nginx limit_req) 수
const wafLatency = new Trend('aegis_waf_latency', true);         // 응답시간 추이
const correctVerdict = new Rate('aegis_correct_verdict');        // 기대대로 동작한 비율

// ---------------------------------------------------------
// 요청 풀: 정상 / 공격
// ---------------------------------------------------------
// 대상 사이트에 실제로 있는 경로로 바꿔야 한다(없는 경로는 404 → 오판정 + R-SCAN 오탐).
//   예: MuShop  -e NORMAL_PATHS=/,/index.html,/api/config
const NORMAL_PATHS = (__ENV.NORMAL_PATHS || '/,/index.html,/ping').split(',');
const normalRequests = NORMAL_PATHS.map((path) => (
  { method: 'GET', path: path.trim(), headers: { 'User-Agent': 'Mozilla/5.0' } }
));

const attackRequests = [
  // Shadow API
  { method: 'GET', path: '/api/v1/admin', headers: {} },
  // Scanner UA
  { method: 'GET', path: '/', headers: { 'User-Agent': 'sqlmap/1.7' } },
  // Internal resource
  { method: 'GET', path: '/actuator', headers: {} },
  // SQL Injection
  { method: 'GET', path: "/api/v1/users?id=1%27%20OR%20%271%27%3D%271", headers: {} },
  // XSS
  { method: 'GET', path: '/api/v1/search?q=%3Cscript%3Ealert(1)%3C/script%3E', headers: {} },
  // Mass Assignment
  { method: 'POST', path: '/submit', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'admin' }) },
];

// ---------------------------------------------------------
// 시나리오별 부하 프로파일
// ---------------------------------------------------------
const profiles = {
  // 워밍업: 스크립트 검증용 1분
  warmup: {
    executor: 'constant-vus',
    vus: 10,
    duration: '1m',
  },

  // 정상 트래픽: 점진적 증가 → 최대 부하 → 감소
  normal: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '30s', target: 20 },   // 워밍업
      { duration: '1m', target: 50 },    // 부하 증가
      { duration: '2m', target: 100 },   // 최대 부하 유지
      { duration: '30s', target: 0 },    // 쿨다운
    ],
  },
  // 공격 트래픽: WAF가 403 쏟아낼 때 안정적인지
  attack: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '30s', target: 30 },
      { duration: '2m', target: 80 },
      { duration: '30s', target: 0 },
    ],
  },
  // 혼합: 현실적인 트래픽 비율
  mixed: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '30s', target: 30 },
      { duration: '2m', target: 100 },
      { duration: '1m', target: 100 },
      { duration: '30s', target: 0 },
    ],
  },
  // 장시간 안정성: 낮은 부하로 오래 (메모리 누수 점검)
  soak: {
    executor: 'constant-vus',
    vus: 30,
    duration: '30m',   // 발표 전엔 2h 이상 권장
  },
};

export const options = {
  // 기본 요약엔 p(99) 가 없어 handleSummary 의 p99 가 0 으로 찍혔다
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'],
  scenarios: {
    [SCENARIO]: { ...profiles[SCENARIO] },
  },
  thresholds: {
    // 합격 기준 — 환경에 맞춰 조정 (로컬 vs EC2)
    http_req_duration: ['p(95)<800', 'p(99)<2000'],  // p95 800ms, p99 2s 이내
    http_req_failed: ['rate<0.01'],                   // 연결 실패 1% 미만
    aegis_correct_verdict: ['rate>0.99'],             // 99% 이상 기대대로 동작
  },
};

// ---------------------------------------------------------
// 메인 실행 함수
// ---------------------------------------------------------
export default function() {
  let req;
  let isAttack;

  if (SCENARIO === 'normal' || SCENARIO === 'soak' || SCENARIO === 'warmup') {
    req = normalRequests[Math.floor(Math.random() * normalRequests.length)];
    isAttack = false;
  } else if (SCENARIO === 'attack') {
    req = attackRequests[Math.floor(Math.random() * attackRequests.length)];
    isAttack = true;
  } else { // mixed: 80% 정상 + 20% 공격
    if (Math.random() < 0.8) {
      req = normalRequests[Math.floor(Math.random() * normalRequests.length)];
      isAttack = false;
    } else {
      req = attackRequests[Math.floor(Math.random() * attackRequests.length)];
      isAttack = true;
    }
  }

  const headers = Object.assign({}, req.headers);
  if (SPREAD_IPS > 0 && !isAttack) {
    headers['X-Forwarded-For'] = spreadIp();
  }
  const params = { headers, timeout: '10s' };
  const url = `${TARGET}${req.path}`;

  const res = req.method === 'POST'
    ? http.post(url, req.body, params)
    : http.get(url, params);

  // 메트릭 기록
  wafLatency.add(res.timings.duration);

  if (res.status === 403 || res.status === 401) {
    blockedRequests.add(1);
  } else if (res.status === 200) {
    passedRequests.add(1);
  } else if (res.status === 429) {
    rateLimited.add(1);
  }

  // 기대대로 동작했는가?
  //  - 공격 요청: 4xx 로 차단되어야 정상
  //  - 정상 요청: 2xx 로 통과되어야 정상
  const verdict = isAttack
    ? (res.status >= 400 && res.status < 500)
    : (res.status >= 200 && res.status < 400);
  correctVerdict.add(verdict);

  check(res, {
    'status is expected': () => verdict,
    'response time < 2s': (r) => r.timings.duration < 2000,
    'no server error (5xx)': (r) => r.status < 500,
  });

  sleep(Math.random() * 0.5 + 0.1);  // 0.1~0.6초 think time
}

// ---------------------------------------------------------
// 테스트 종료 후 요약
// ---------------------------------------------------------
export function handleSummary(data) {
  const m = data.metrics;
  const get = (name, field, def = 0) =>
    (m[name] && m[name].values && m[name].values[field] !== undefined)
      ? m[name].values[field] : def;

  const summary = `
========================================
 Aegis-3 부하 테스트 결과 [${SCENARIO}]
========================================
 대상:          ${TARGET}
 총 요청:       ${get('http_reqs', 'count')}
 처리량(RPS):   ${get('http_reqs', 'rate').toFixed(1)}

 [응답 시간]
 평균:          ${get('http_req_duration', 'avg').toFixed(1)} ms
 p50:           ${get('http_req_duration', 'med').toFixed(1)} ms
 p95:           ${get('http_req_duration', 'p(95)').toFixed(1)} ms
 p99:           ${get('http_req_duration', 'p(99)').toFixed(1)} ms
 최대:          ${get('http_req_duration', 'max').toFixed(1)} ms

 [WAF 판정]
 통과(2xx):     ${get('aegis_passed_requests', 'count')}
 차단(401/403): ${get('aegis_blocked_requests', 'count')}
 제한(429):     ${get('aegis_rate_limited', 'count')}
 정확도:        ${(get('aegis_correct_verdict', 'rate') * 100).toFixed(2)} %

 [안정성]
 실패율:        ${(get('http_req_failed', 'rate') * 100).toFixed(3)} %  (2xx/3xx/401/403 외 응답·연결 실패)
========================================
`;

  return {
    'stdout': summary,
    [`results_${SCENARIO}_${Date.now()}.json`]: JSON.stringify(data, null, 2),
  };
}