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
const crypto = require('crypto');
const { URL } = require('url');
const { getHeadersObject } = require('./userAgents');
const { detectRateLimit } = require('./rateLimitDetection');
const { detectGeoBlocking, getBlockingMessage } = require('./geoBlockDetection');
const { resolveDns, extractHostname } = require('./dnsMonitoring');
const { getCookieHeader, storeCookies } = require('./cookieJar');
const { followRedirects, detectGeoRedirect, REDIRECT_STATUS_CODES } = require('./redirectTracking');
const { validateContent } = require('./contentValidation');

const app = express();
app.use(express.json());

const PORT = process.env.PROBE_PORT || 3002;
const PROBE_SECRET = process.env.PROBE_SECRET || '';
const PROBE_REGION = process.env.PROBE_REGION || 'unknown';

// Geo-blocking detection
const GEO_BLOCKING_STATUS_CODES = [403, 451, 406];
const GEO_BLOCKING_PATTERNS = [
  'access denied',
  'forbidden',
  'geo-blocked',
  'not available in your region',
  'country block',
  'region block',
  'blocked in your country',
  'geographical restriction',
];

function detectGeoBlocking(
  statusCode: number | null,
  errorMessage: string | null,
  responseBody?: string
): { isGeoBlocked: boolean; indicators: string[] } {
  const indicators: string[] = [];

  if (statusCode && GEO_BLOCKING_STATUS_CODES.includes(statusCode)) {
    indicators.push(`Status code ${statusCode} indicates potential geo-blocking`);
  }

  if (errorMessage) {
    const lowerError = errorMessage.toLowerCase();
    for (const pattern of GEO_BLOCKING_PATTERNS) {
      if (lowerError.includes(pattern)) {
        indicators.push(`Error message contains "${pattern}"`);
      }
    }
  }

  if (responseBody) {
    const lowerBody = responseBody.toLowerCase();
    for (const pattern of GEO_BLOCKING_PATTERNS) {
      if (lowerBody.includes(pattern)) {
        indicators.push(`Response body contains "${pattern}"`);
      }
    }
  }

  return { isGeoBlocked: indicators.length > 0, indicators };
}

interface ProbeRequest {
  monitorId: string;
  url: string;
  method: string;
  monitorType: string;
  timeoutSeconds: number;
  expectedStatus?: number;
  headers?: Record<string, string>;
  pingPort?: number;
  ignoreSslErrors?: boolean;
  degradedThresholdMs?: number;
  enableCookies?: boolean;
  cookieTtlSeconds?: number;
  // Content validation configuration
  contentValidation?: any;
}

interface ProbeResult {
  monitorId: string;
  region: string;
  status: 'up' | 'down' | 'degraded';
  statusCode: number | null;
  responseTimeMs: number;
  errorMessage: string | null;
  isGeoBlocked: boolean;
  geoBlockingIndicators: string[];
  // Response data (limited to first 100KB for efficiency)
  responseBody?: string;
  contentValidated?: boolean;
  contentHash?: string;
  validationErrors?: string[];
  responseSize?: number;
  // Redirect tracking
  redirectCount?: number;
  finalUrl?: string;
  redirectChain?: any;
  // Timing breakdown
  timingBreakdown?: any;
  // Rate limiting info
  rateLimitInfo?: any;
}

async function performHttpCheck(config: ProbeRequest): Promise<ProbeResult> {
  const { url, method = 'GET', expectedStatus = 200, timeout = 30000, headers = {}, degradedThresholdMs, monitorId, enableCookies, cookieTtlSeconds, contentValidation } = config;

  const startTime = Date.now();
  let statusCode: number | null = null;
  let errorMessage: string | null = null;
  let responseBody: string | undefined;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.timeoutSeconds * 1000);

    // Create custom agent if SSL errors should be ignored
    const defaultHeaders = getHeadersObject('rotate');

    // Prepare request headers
    const requestHeaders = {
      ...defaultHeaders,
      ...headers,
    };

    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method,
      timeout,
      headers: requestHeaders,
      rejectUnauthorized: !config.ignoreSslErrors,
      agent: new https.Agent({ rejectUnauthorized: !config.ignoreSslErrors }),
    };

    const response = await fetch(url, options);

    clearTimeout(timeoutId);
    statusCode = response.status;

    try {
      responseBody = await response.text();
    } catch {
      responseBody = undefined;
    }

    if (config.expectedStatus && statusCode !== config.expectedStatus) {
      status = 'down';
      errorMessage = `Expected status ${config.expectedStatus}, got ${statusCode}`;
    }
  } catch (error) {
    status = 'down';
    errorMessage = error.name === 'AbortError' ? 'Request timeout' : error.message;
  }

  const responseTimeMs = Date.now() - startTime;

  if (config.expectedStatus && statusCode !== config.expectedStatus) {
    status = 'down';
    errorMessage = `Expected status ${config.expectedStatus}, got ${statusCode}`;
  }

  if (status === 'up' && config.degradedThresholdMs && responseTimeMs > config.degradedThresholdMs) {
    status = 'degraded';
    errorMessage = `Response time ${responseTimeMs}ms exceeded threshold ${config.degradedThresholdMs}ms`;
  }

  const geoBlockCheck = detectGeoBlocking(statusCode, errorMessage, responseBody);

  console.log(`[PROBE:${PROBE_REGION}] ${config.url}: ${status} - ${responseTimeMs}ms${geoBlockCheck.isGeoBlocked ? ' [GEO-BLOCKED]' : ''}`);

  // Content validation (Phase 2.2) - only for HTTP checks with response body
  let contentValidated: boolean | undefined = undefined;
  let contentHash: string | undefined = undefined;
  let validationErrors: string[] | undefined = undefined;
  const responseSize = responseBody ? Buffer.byteLength(responseBody, 'utf8') : undefined;

  if (config.method !== 'tcp_ping' && config.method !== 'http_head' && responseBody) {
    try {
      const validationResult = await validateContent(responseBody, contentValidation);

      if (validationResult) {
        contentValidated = validationResult.passed;
        contentHash = validationResult.contentHash || undefined;
        validationErrors = validationResult.errors.length > 0 ? validationResult.errors : undefined;
        responseSize = validationResult.responseSize;

        if (!validationResult.passed) {
          console.log(`[PROBE:${PROBE_REGION}] Content validation failed: ${validationErrors?.join(', ')}`);
        }
      }
    } catch (error) {
      console.error(`[PROBE:${PROBE_REGION}] Content validation error:`, (error as Error).message);
      validationErrors = [error.message];
    }
  }

  return {
    monitorId: config.monitorId,
    region: PROBE_REGION,
    status,
    statusCode,
    responseTimeMs,
    errorMessage,
    isGeoBlocked: geoBlockCheck.isGeoBlocked,
    geoBlockingIndicators: geoBlockCheck.indicators,
    responseBody,
    contentValidated,
    contentHash,
    validationErrors,
    responseSize,
  };
}

async function performTcpCheck(config: ProbeRequest): Promise<ProbeResult> {
  const { host, port, timeout, degradedThresholdMs } = config;
  const startTime = Date.now();
  let status: 'up' | 'down' | 'degraded' = 'up';
  let errorMessage: string | null = null;

  try {
    let tcpHost = host;
    if (host.includes('://')) {
      tcpHost = host.split('://')[1];
    }
    host = host.split('/')[0].split(':')[0];

    const tcpPort = port || 80;
    const timeoutMs = timeout * 1000;

    await new Promise<void>((resolve, reject) => {
      const socket = new net.Socket();

      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error('Connection timeout'));
      }, timeoutMs);

      socket.connect(port, host, () => {
        clearTimeout(timer);
        socket.destroy();
        resolve();
      });

      socket.on('error', (err) => {
        clearTimeout(timer);
        socket.destroy();
        reject(err);
      });
    });
  } catch (error: any) {
    status = 'down';
    errorMessage = error.message;
  }

  const responseTimeMs = Date.now() - startTime;

  if (status === 'up' && degradedThresholdMs && responseTimeMs > degradedThresholdMs) {
    status = 'degraded';
    errorMessage = `Response time ${responseTimeMs}ms exceeded threshold ${degradedThresholdMs}ms`;
  }

  console.log(`[PROBE:${PROBE_REGION}:TCP] ${host}:${port}: ${status} - ${responseTimeMs}ms`);

  return {
    monitorId: config.monitorId,
    region: PROBE_REGION,
    status,
    statusCode: null,
    responseTimeMs,
    errorMessage,
    isGeoBlocked: false,
    geoBlockingIndicators: [],
    responseBody: undefined,
    contentValidated: undefined,
    contentHash: undefined,
    validationErrors: undefined,
    responseSize: undefined,
  };
}

// Authentication middleware
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

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    region: PROBE_REGION,
    version: '1.0.0',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// Check endpoint
app.post('/check', authMiddleware, async (req, res) => {
  try {
    const config: ProbeRequest = req.body;

    console.log(`[PROBE] Received check request for ${config.url}`);

    let result: ProbeResult;

    switch (config.monitorType) {
      case 'tcp_ping':
        result = await performTcpCheck(config);
        break;
      case 'http_head':
        result = await performHttpCheck({ ...config, method: 'HEAD' });
        break;
      case 'http':
      default:
        result = await performHttpCheck(config);
        break;
    }

    res.json(result);
  } catch (error) {
    console.error('[PROBE] Error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, '0.0.0', () => {
  console.log(`
╔═════════════════════════════════════════════════╗
║       StatusBeacon Probe v1.0.0                   ║
║  Port:   ${PORT.toString().padEnd(44)}                    ║
╠═════════════════════════════════════════════╝
  `);
});
