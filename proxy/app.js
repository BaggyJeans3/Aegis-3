const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const redis = require('redis');
const { v4: uuidv4 } = require('uuid');
const pool = require('./db');
require('dotenv').config();

const app = express();

app.use(express.json());
// 1. 루트 경로 (/) 정의: 404 방지 및 시스템 상태 확인용
app.get('/', (req, res) => {
    res.json({
        status: "success",
        message: "Aegis-3 Security Proxy is running."
    });
});

// 2. 마스킹 테스트용 경로 (/user): Nginx의 sub_filter 작동 확인용
app.get('/user', (req, res) => {
    res.json({
        name: "홍길동",
        phone: "010-9999-8888", // Nginx에서 010-9999-****로 바뀌어야 함
        ssn: "900101-1234567"   // Nginx에서 900101-1******로 바뀌어야 함
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
  return (
    req.headers['cf-connecting-ip'] ||
    req.headers['x-forwarded-for'] ||
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

async function pushSecurityEvent(eventData) {
  const event = {
    event_id: uuidv4(),
    timestamp: new Date().toISOString(),
    ...eventData,
  };

  console.log('[SECURITY EVENT]', JSON.stringify(event));

  if (redisClient.isOpen) {
    await redisClient.lPush('aegis:security-events', JSON.stringify(event));
  }
}

function sendHoneypotResponse(req, res, route) {
  const clientIp = getClientIp(req);

  pushSecurityEvent({
    event_type: 'honeypot_hit',
    tenant_id: route?.tenant_id || null,
    company_name: route?.company_name || null,
    target_domain: normalizeHost(req.headers.host),
    request_path: req.path,
    method: req.method,
    attacker_ip: clientIp,
    user_agent: req.headers['user-agent'] || null,
    action_taken: 'honeypot',
    description: route?.description || 'honeypot route matched',
  }).catch((error) => {
    console.error('[REDIS LOG ERROR]', error.message);
  });

  return res.status(200).json({
    status: 'ok',
    message: 'debug endpoint initialized',
    trace_id: `decoy-${uuidv4()}`,
  });
}

function sendBlockedResponse(req, res, route) {
  const clientIp = getClientIp(req);

  pushSecurityEvent({
    event_type: 'blocked_request',
    tenant_id: route?.tenant_id || null,
    company_name: route?.company_name || null,
    target_domain: normalizeHost(req.headers.host),
    request_path: req.path,
    method: req.method,
    attacker_ip: clientIp,
    user_agent: req.headers['user-agent'] || null,
    action_taken: 'block',
    description: route?.description || 'blocked by policy',
  }).catch((error) => {
    console.error('[REDIS LOG ERROR]', error.message);
  });

  return res.status(403).json({
    status: 'blocked',
    message: 'Blocked by Aegis-3 security policy',
  });
}

function sendLogOnlyResponse(req, route) {
  const clientIp = getClientIp(req);

  pushSecurityEvent({
    event_type: 'log_only',
    tenant_id: route?.tenant_id || null,
    company_name: route?.company_name || null,
    target_domain: normalizeHost(req.headers.host),
    request_path: req.path,
    method: req.method,
    attacker_ip: clientIp,
    user_agent: req.headers['user-agent'] || null,
    action_taken: 'log_only',
    description: route?.description || 'logged only',
  }).catch((error) => {
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
    await pushSecurityEvent({
      event_type: 'no_matching_route',
      tenant_id: null,
      company_name: null,
      target_domain: normalizeHost(host),
      request_path: path,
      method,
      attacker_ip: clientIp,
      user_agent: req.headers['user-agent'] || null,
      action_taken: 'block',
      description: 'No matching route found',
    });

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

      return createProxyMiddleware({
        target: matchedRoute.target_origin,
        changeOrigin: true,
        xfwd: true,
      })(req, res, next);

    case 'proxy':
      if (!isValidOrigin(matchedRoute.target_origin)) {
        return res.status(500).json({
          status: 'error',
          message: 'Invalid target origin for proxy route',
        });
      }

      return createProxyMiddleware({
        target: matchedRoute.target_origin,
        changeOrigin: true,
        xfwd: true,
      })(req, res, next);

    default:
      return res.status(500).json({
        status: 'error',
        message: 'Unknown route action',
      });
  }
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
