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

// 커스텀 메트릭
const blockedRequests = new Counter('aegis_blocked_requests');   // 403 차단 수
const passedRequests = new Counter('aegis_passed_requests');     // 200 통과 수
const wafLatency = new Trend('aegis_waf_latency', true);         // 응답시간 추이
const correctVerdict = new Rate('aegis_correct_verdict');        // 기대대로 동작한 비율

// ---------------------------------------------------------
// 요청 풀: 정상 / 공격
// ---------------------------------------------------------
const normalRequests = [
  { method: 'GET', path: '/', headers: { 'User-Agent': 'Mozilla/5.0' } },
  { method: 'GET', path: '/index.html', headers: { 'User-Agent': 'Mozilla/5.0' } },
  { method: 'GET', path: '/ping', headers: { 'User-Agent': 'Mozilla/5.0' } },
];

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

  const params = { headers: req.headers, timeout: '10s' };
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
 차단(4xx):     ${get('aegis_blocked_requests', 'count')}
 정확도:        ${(get('aegis_correct_verdict', 'rate') * 100).toFixed(2)} %

 [안정성]
 연결 실패율:   ${(get('http_req_failed', 'rate') * 100).toFixed(3)} %
========================================
`;

  return {
    'stdout': summary,
    [`results_${SCENARIO}_${Date.now()}.json`]: JSON.stringify(data, null, 2),
  };
}