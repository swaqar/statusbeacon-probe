/**
 * StatusBeacon Probe Service
 * 
 * Lightweight, standalone probe that performs HTTP/TCP checks
 * for the main StatusBeacon server.
 * 
 * Setup:
 *   1. Copy this folder to your probe server
 *   2. npm install
 *   3. PROBE_SECRET=your-secret PORT=3002 node probe.js
 * 
 * Or use the setup script: curl -s https://your-domain/probe-setup.sh | bash
 */

const express = require('express');
const http = require('http');
const https = require('https');
const net = require('net');
const { URL } = require('url');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3002;
const PROBE_SECRET = process.env.PROBE_SECRET || '';
const PROBE_REGION = process.env.PROBE_REGION || 'unknown';

// Geo-blocking detection patterns
const GEO_BLOCKING_STATUS_CODES = [403, 451, 406];
const GEO_BLOCKING_PATTERNS = [
  'geo', 'region', 'country', 'location', 'blocked', 'restricted',
  'not available', 'access denied', 'forbidden', 'cloudflare'
];

function detectGeoBlocking(statusCode, errorMessage, responseBody) {
  if (GEO_BLOCKING_STATUS_CODES.includes(statusCode)) {
    const combined = `${errorMessage || ''} ${responseBody || ''}`.toLowerCase();
    for (const pattern of GEO_BLOCKING_PATTERNS) {
      if (combined.includes(pattern)) {
        return { detected: true, reason: `Possible geo-blocking: ${pattern} detected in response` };
      }
    }
  }
  return { detected: false };
}

// Perform HTTP check
async function performHttpCheck(config) {
  const { url, method = 'GET', expectedStatus = 200, timeout = 30000, headers = {}, degradedThresholdMs } = config;
  const startTime = Date.now();

  return new Promise((resolve) => {
    try {
      const parsedUrl = new URL(url);
      const isHttps = parsedUrl.protocol === 'https:';
      const httpModule = isHttps ? https : http;

      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: method,
        timeout: timeout,
        headers: {
          'User-Agent': 'StatusBeacon-Probe/1.0',
          ...headers
        },
        rejectUnauthorized: !config.ignoreSslErrors
      };

      const req = httpModule.request(options, (res) => {
        let body = '';
        res.on('data', chunk => { body += chunk.toString().slice(0, 1000); }); // Limit body size
        res.on('end', () => {
          const responseTime = Date.now() - startTime;
          const statusCode = res.statusCode;
          const isUp = statusCode === expectedStatus ||
                       (expectedStatus === 200 && statusCode >= 200 && statusCode < 300);

          // Check if response time exceeds degraded threshold (only if status is currently 'up')
          let status = isUp ? 'up' : 'down';
          let errorMsg = isUp ? null : `Expected ${expectedStatus}, got ${statusCode}`;
          if (status === 'up' && degradedThresholdMs && responseTime > degradedThresholdMs) {
            status = 'degraded';
            errorMsg = `Response time ${responseTime}ms exceeded threshold ${degradedThresholdMs}ms`;
          }

          const geoBlocking = detectGeoBlocking(statusCode, '', body);

          resolve({
            status,
            statusCode,
            responseTimeMs: responseTime,
            error: errorMsg,
            geoBlocking,
            region: PROBE_REGION
          });
        });
      });

      req.on('error', (error) => {
        const responseTime = Date.now() - startTime;
        const geoBlocking = detectGeoBlocking(0, error.message, '');
        
        resolve({
          status: 'down',
          statusCode: 0,
          responseTimeMs: responseTime,
          error: error.message,
          geoBlocking,
          region: PROBE_REGION
        });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({
          status: 'down',
          statusCode: 0,
          responseTimeMs: timeout,
          error: 'Request timeout',
          geoBlocking: { detected: false },
          region: PROBE_REGION
        });
      });

      req.end();
    } catch (error) {
      resolve({
        status: 'down',
        statusCode: 0,
        responseTimeMs: Date.now() - startTime,
        error: error.message,
        geoBlocking: { detected: false },
        region: PROBE_REGION
      });
    }
  });
}

// Perform TCP check
async function performTcpCheck(config) {
  const { host, port, timeout = 10000, degradedThresholdMs } = config;
  const startTime = Date.now();

  return new Promise((resolve) => {
    const socket = new net.Socket();

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      const responseTime = Date.now() - startTime;
      socket.destroy();

      // Check if response time exceeds degraded threshold
      let status = 'up';
      let errorMsg = null;
      if (degradedThresholdMs && responseTime > degradedThresholdMs) {
        status = 'degraded';
        errorMsg = `Response time ${responseTime}ms exceeded threshold ${degradedThresholdMs}ms`;
      }

      resolve({
        status,
        responseTimeMs: responseTime,
        error: errorMsg,
        region: PROBE_REGION
      });
    });
    
    socket.on('error', (error) => {
      const responseTime = Date.now() - startTime;
      socket.destroy();
      resolve({
        status: 'down',
        responseTimeMs: responseTime,
        error: error.message,
        region: PROBE_REGION
      });
    });
    
    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        status: 'down',
        responseTimeMs: timeout,
        error: 'Connection timeout',
        region: PROBE_REGION
      });
    });
    
    try {
      socket.connect(port, host);
    } catch (error) {
      resolve({
        status: 'down',
        responseTimeMs: Date.now() - startTime,
        error: error.message,
        region: PROBE_REGION
      });
    }
  });
}

// Auth middleware
function authMiddleware(req, res, next) {
  if (!PROBE_SECRET) {
    console.warn('Warning: PROBE_SECRET not set, authentication disabled');
    return next();
  }
  
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader !== `Bearer ${PROBE_SECRET}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// Health endpoint (no auth required)
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    region: PROBE_REGION,
    version: '1.0.0',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// Check endpoint (auth required)
app.post('/check', authMiddleware, async (req, res) => {
  try {
    const { url, method, expectedStatus, timeout, headers, ignoreSslErrors, degradedThresholdMs, monitorType, host, port } = req.body;

    let result;

    if (monitorType === 'tcp' || (!url && host && port)) {
      result = await performTcpCheck({ host, port, timeout, degradedThresholdMs });
    } else if (url) {
      result = await performHttpCheck({ url, method, expectedStatus, timeout, headers, ignoreSslErrors, degradedThresholdMs });
    } else {
      return res.status(400).json({ error: 'Missing url or host/port' });
    }

    res.json(result);
  } catch (error) {
    console.error('Check error:', error);
    res.status(500).json({
      status: 'error',
      error: error.message,
      region: PROBE_REGION
    });
  }
});

// Info endpoint
app.get('/', (req, res) => {
  res.json({
    name: 'StatusBeacon Probe',
    version: '1.0.0',
    region: PROBE_REGION,
    endpoints: {
      health: 'GET /health',
      check: 'POST /check (requires auth)'
    }
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔═══════════════════════════════════════════════════════╗
║           StatusBeacon Probe v1.0.0                   ║
╠═══════════════════════════════════════════════════════╣
║  Port:   ${PORT.toString().padEnd(44)}║
║  Region: ${PROBE_REGION.padEnd(44)}║
║  Auth:   ${(PROBE_SECRET ? 'Enabled' : 'DISABLED (set PROBE_SECRET!)').padEnd(44)}║
╚═══════════════════════════════════════════════════════╝
  `);
});
