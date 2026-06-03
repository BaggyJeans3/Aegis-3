const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const redis = require('redis');
const { v4: uuidv4 } = require('uuid');
const pool = require('./db');
require('dotenv').config();

const app = express();

app.use(express.json());

// ──────────────────────────────────────────────────────────
// [Aegis-3 SOAR] IP 평판 1차 차단
// 24시간 내 악성 판정된 IP는 라우팅·로깅·LLM 어느 단계도 거치지 않고
// 즉시 403으로 차단한다. 같은 공격자의 반복 요청 비용을 최소화한다.
// Redis 장애 시 fail-open — 차단 못 하더라도 정상 요청은 통과시킨다.
// 모든 라우트보다 먼저 실행되도록 express.json() 바로 다음에 배치한다.
// ──────────────────────────────────────────────────────────
app.use(async (req, res, next) => {
  const clientIp = getClientIp(req);

  if (clientIp && clientIp !== 'unknown') {
    try {
      const isBlocked = await redisClient.exists(`aegis:blacklist:${clientIp}`);
      if (isBlocked) {
        console.log(`[BLOCKED] ${req.method} ${req.headers.host}${req.path} from ${clientIp} — IP blacklist hit`);
        // 통계 카운터 (대시보드용, 실패해도 차단 동작은 계속)
        redisClient.incr('aegis:stats:proxy_blocked').catch(() => {});
        return res.status(403).json({
          status: 'forbidden',
          message: 'Access denied',
        });
      }
    } catch (err) {
      console.warn(`[Aegis-3] Redis 블랙리스트 조회 실패(ip=${clientIp}): ${err.message} — fail-open으로 요청 통과`);
    }
  }

  return next();
});

// 1. 루트 경로 (/) 정의: 404 방지 및 시스템 상태 확인용
app.get('/', (req, res) => {
  res.json({
    status: 'success',
    message: 'Aegis-3 Security Proxy is running.',
  });
});

// 2. 마스킹 테스트용 경로 (/user): Nginx의 sub_filter 작동 확인용
app.get('/user', (req, res) => {
  res.json({
    name: '홍길동',
    phone: '010-9999-8888', // Nginx에서 010-9999-****로 바뀌어야 함
    ssn: '900101-1234567', // Nginx에서 900101-1******로 바뀌어야 함
  });
});

const PORT = process.env.PORT || 3000;

let routeCache = [];

const redisClient = redis.createClient({
  socket: {
    host: process.env.REDIS_HOST || 'redis',
    port: Number(process.env.REDIS_PORT || 6379),
  },
});

function normalizeHost(hostHeader) {
  if (!hostHeader) return '';
  return hostHeader.split(':')[0].toLowerCase();
}

function getClientIp(req) {
  const forwardedFor = req.headers['x-forwarded-for'];

  // [수정] Nginx/Cloudflare 뒤에 있을 때 X-Forwarded-For에는
  // "client, proxy1, proxy2"처럼 여러 IP가 들어갈 수 있으므로 첫 번째 IP를 우선 사용한다.
  if (forwardedFor) {
    return String(forwardedFor).split(',')[0].trim();
  }

  return (
    req.headers['cf-connecting-ip'] ||
    req.ip ||
    'unknown'
  );
}

function matchPath(pattern, requestPath) {
  if (!pattern) return false;

  if (pattern === '/*') {
    return true;
  }

  if (pattern.endsWith('/*')) {
    const prefix = pattern.slice(0, -1);
    return requestPath.startsWith(prefix);
  }

  return pattern === requestPath;
}

function isValidOrigin(origin) {
  if (!origin) return false;

  try {
    const parsed = new URL(origin);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch (error) {
    return false;
  }
}

async function loadRoutesFromDB() {
  const query = `
    SELECT
      r.route_id,
      r.tenant_id,
      r.inbound_domain,
      r.path_pattern,
      r.target_origin,
      r.priority,
      r.allowed_methods,
      r.action_on_match,
      r.is_active,
      r.description,
      t.company_name,
      t.status AS tenant_status
    FROM routers r
    JOIN tenants t ON r.tenant_id = t.tenant_id
    WHERE r.is_active = TRUE
      AND t.status = 'active'
    ORDER BY r.priority ASC
  `;

  const result = await pool.query(query);
  routeCache = result.rows;

  console.log(`[ROUTE CACHE] ${routeCache.length} routes loaded`);
}

function findRouteFromCache(host, path, method) {
  const normalizedHost = normalizeHost(host);

  const domainRules = routeCache
    .filter((rule) => {
      return (
        rule.inbound_domain === normalizedHost &&
        Array.isArray(rule.allowed_methods) &&
        rule.allowed_methods.includes(method)
      );
    })
    .sort((a, b) => a.priority - b.priority);

  for (const rule of domainRules) {
    if (matchPath(rule.path_pattern, path)) {
      return rule;
    }
  }

  return null;
}

/**
 * [추가] Analyzer 입력용으로 Redis 이벤트 로그 필드를 통일한다.
 *
 * 기존 Redis 로그:
 * - target_domain, request_path, attacker_ip, action_taken
 *
 * 수정 후 Redis 로그:
 * - host, path, ip, action_on_match, status_code
 *
 * 이유:
 * Risk Score Analyzer 코드가 log.get("path"), log.get("ip"),
 * log.get("status_code") 같은 flat 필드명을 기준으로 분석하기 때문이다.
 */
function buildAnalyzerEvent(req, route, options = {}) {
  const eventId = uuidv4();
  const traceId = req.headers['x-request-id'] || req.headers['x-trace-id'] || `trace-${eventId}`;
  const queryIndex = req.originalUrl.indexOf('?');

  // [추가] payload 탐지를 위해 query/body/headers를 넣되,
  // 너무 큰 body가 Redis에 들어가지 않도록 JSON 문자열 기준으로 길이를 제한한다.
  let requestBody = '';

  if (req.body && Object.keys(req.body).length > 0) {
    try {
      requestBody = JSON.stringify(req.body).slice(0, 2000);
    } catch (error) {
      requestBody = '[unserializable_body]';
    }
  }

  return {
    event_id: eventId,
    trace_id: traceId,
    timestamp: new Date().toISOString(),

    // [추가] 이벤트 성격과 분석 범위를 분리한다.
    // access_event는 정상 proxy 요청의 요청량 폭증 탐지용,
    // honeypot/block/log_only/no_route는 full 분석 대상으로 사용한다.
    event_type: options.event_type || 'security_event',
    analysis_profile: options.analysis_profile || 'full',

    tenant_id: route?.tenant_id || null,
    company_name: route?.company_name || null,

    ip: getClientIp(req),
    session_id: req.headers['x-session-id'] || req.headers['cookie'] || 'unknown',

    method: req.method,
    host: normalizeHost(req.headers.host),
    path: req.path,
    query: queryIndex >= 0 ? req.originalUrl.slice(queryIndex + 1) : '',
    headers: {
      'user-agent': req.headers['user-agent'] || null,
      'x-forwarded-for': req.headers['x-forwarded-for'] || null,
      'cf-connecting-ip': req.headers['cf-connecting-ip'] || null,
      authorization: req.headers.authorization ? '[present]' : null,
      'content-type': req.headers['content-type'] || null,
    },
    body: requestBody,

    // [추가] status_code는 404/403/200처럼 Analyzer 탐지 기준에서 필요하다.
    // proxy 요청은 이 시점에 origin 응답을 아직 받기 전이라 0으로 둔다.
    // 이후 Worker/ProxyRes 단계에서 실제 응답코드로 보강할 수 있다.
    status_code: options.status_code ?? 0,

    action_on_match: options.action_on_match || route?.action_on_match || 'unknown',
    route_id: route?.route_id || null,
    route_description: route?.description || null,
  };
}

async function pushSecurityEvent(event) {
  console.log('[SECURITY EVENT]', JSON.stringify(event));

  if (redisClient.isOpen) {
    await redisClient.lPush('aegis:security-events', JSON.stringify(event));
  }
}

function sendHoneypotResponse(req, res, route) {
  // [수정] honeypot 요청은 full 분석 대상이다.
  // 민감 경로 접근, payload 우회, 반복 접근 등을 모두 Analyzer에서 확인할 수 있다.
  const event = buildAnalyzerEvent(req, route, {
    event_type: 'honeypot_hit',
    analysis_profile: 'full',
    status_code: 200,
    action_on_match: 'honeypot',
  });

  pushSecurityEvent(event).catch((error) => {
    console.error('[REDIS LOG ERROR]', error.message);
  });

  return res.status(200).json({
    status: 'ok',
    message: 'debug endpoint initialized',
    trace_id: `decoy-${uuidv4()}`,
  });
}

function sendBlockedResponse(req, res, route) {
  // [수정] block 요청은 full 분석 대상이다.
  // 이미 정책상 차단된 요청이므로 위험 이벤트로 기록한다.
  const event = buildAnalyzerEvent(req, route, {
    event_type: 'blocked_request',
    analysis_profile: 'full',
    status_code: 403,
    action_on_match: 'block',
  });

  pushSecurityEvent(event).catch((error) => {
    console.error('[REDIS LOG ERROR]', error.message);
  });

  return res.status(403).json({
    status: 'blocked',
    message: 'Blocked by Aegis-3 security policy',
  });
}

function sendLogOnlyResponse(req, route) {
  // [수정] log_only 요청은 차단하지 않지만 이상 패턴 분석 대상이다.
  // catch-all 또는 관찰용 규칙에 걸린 요청이므로 full 분석 대상으로 Redis에 넣는다.
  const event = buildAnalyzerEvent(req, route, {
    event_type: 'log_only_event',
    analysis_profile: 'full',
    status_code: 0,
    action_on_match: 'log_only',
  });

  pushSecurityEvent(event).catch((error) => {
    console.error('[REDIS LOG ERROR]', error.message);
  });
}

function sendAccessEvent(req, route) {
  // [추가] 정상 proxy 요청도 Redis에 넣는다.
  // 이유: 정상 경로라도 60초 안에 과도하게 반복되면 API 자원 사용량 초과 탐지 대상이기 때문이다.
  // 단, 위험 이벤트가 아니므로 event_type은 access_event,
  // analysis_profile은 rate_only로 분리한다.
  const event = buildAnalyzerEvent(req, route, {
    event_type: 'access_event',
    analysis_profile: 'rate_only',
    status_code: 0,
    action_on_match: 'proxy',
  });

  pushSecurityEvent(event).catch((error) => {
    console.error('[REDIS LOG ERROR]', error.message);
  });
}

app.get('/health', (req, res) => {
  return res.status(200).json({
    status: 'ok',
    service: 'aegis3-proxy',
    route_count: routeCache.length,
  });
});

app.post('/admin/routes/refresh', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];

  if (!adminKey || adminKey !== process.env.ADMIN_REFRESH_KEY) {
    return res.status(401).json({
      status: 'unauthorized',
      message: 'Invalid admin key',
    });
  }

  try {
    await loadRoutesFromDB();

    return res.status(200).json({
      status: 'ok',
      message: 'Route cache refreshed',
      route_count: routeCache.length,
    });
  } catch (error) {
    console.error('[ROUTE REFRESH ERROR]', error);

    return res.status(500).json({
      status: 'error',
      message: 'Failed to refresh route cache',
    });
  }
});

app.use(async (req, res, next) => {
  const host = req.headers.host;
  const path = req.path;
  const method = req.method;
  const clientIp = getClientIp(req);

  console.log(`[REQUEST] ${method} ${host}${path} from ${clientIp}`);

  const matchedRoute = findRouteFromCache(host, path, method);

  if (!matchedRoute) {
    // [수정] route가 없는 요청도 Analyzer 입력 필드명에 맞춰 Redis에 기록한다.
    // 고객사/라우팅 정책에 없는 도메인이나 경로를 찌르는 스캐닝 가능성이 있기 때문이다.
    const event = buildAnalyzerEvent(req, null, {
      event_type: 'no_matching_route',
      analysis_profile: 'full',
      status_code: 404,
      action_on_match: 'no_route',
    });

    await pushSecurityEvent(event);

    return res.status(404).json({
      status: 'not_found',
      message: 'No matching route found',
    });
  }

  console.log(
    `[MATCHED] ${matchedRoute.inbound_domain} ${matchedRoute.path_pattern} -> ${matchedRoute.action_on_match}`
  );

  switch (matchedRoute.action_on_match) {
    case 'block':
      return sendBlockedResponse(req, res, matchedRoute);

    case 'honeypot':
      return sendHoneypotResponse(req, res, matchedRoute);

    case 'log_only':
      sendLogOnlyResponse(req, matchedRoute);

      if (!isValidOrigin(matchedRoute.target_origin)) {
        return res.status(500).json({
          status: 'error',
          message: 'Invalid target origin for log_only route',
        });
      }

      req.targetOrigin = matchedRoute.target_origin;
      return next();

    case 'proxy':
      if (!isValidOrigin(matchedRoute.target_origin)) {
        return res.status(500).json({
          status: 'error',
          message: 'Invalid target origin for proxy route',
        });
      }

      // [추가] 정상 proxy 요청도 access_event로 Redis에 넣는다.
      // 위험 이벤트가 아니라 요청량 폭증 탐지용 이벤트다.
      sendAccessEvent(req, matchedRoute);

      req.targetOrigin = matchedRoute.target_origin;
      return next();

    default:
      return res.status(500).json({
        status: 'error',
        message: 'Unknown route action',
      });
  }
});

// 단일 프록시 미들웨어 인스턴스 생성 (router 옵션을 통한 동적 라우팅)
const dynamicProxyMiddleware = createProxyMiddleware({
  target: 'http://localhost', // 기본값 (router 함수에서 덮어씌워짐)
  changeOrigin: true,
  xfwd: true,
  router: (req) => {
    return req.targetOrigin;
  },
});

// targetOrigin이 설정된 요청만 프록시 미들웨어 통과
app.use((req, res, next) => {
  if (req.targetOrigin) {
    return dynamicProxyMiddleware(req, res, next);
  }

  next();
});

async function startServer() {
  try {
    await redisClient.connect();
    console.log('[REDIS] connected');

    await loadRoutesFromDB();

    setInterval(async () => {
      try {
        await loadRoutesFromDB();
      } catch (error) {
        console.error('[ROUTE CACHE AUTO REFRESH ERROR]', error.message);
      }
    }, 30000);

    app.listen(PORT, () => {
      console.log(`Aegis-3 proxy server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('[STARTUP ERROR]', error);
    process.exit(1);
  }
}

startServer();