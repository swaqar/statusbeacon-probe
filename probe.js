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
const { getHeadersObject } = require('./userAgents');
const { detectGeoBlocking, getBlockingMessage } = require('./geoBlockDetection');
const { resolveDns, extractHostname } = require('./dnsMonitoring');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3002;
const PROBE_SECRET = process.env.PROBE_SECRET || '';
const PROBE_REGION = process.env.PROBE_REGION || 'unknown';

// Perform HTTP check
async function performHttpCheck(config) {
  const { url, method = 'GET', expectedStatus = 200, timeout = 30000, headers = {}, degradedThresholdMs } = config;

  // Step 1: Perform DNS resolution first
  const hostname = extractHostname(url);
  const dnsResult = await resolveDns(hostname, 5000);

  const dnsResponseTimeMs = dnsResult.responseTimeMs;
  const dnsResolvedIps = dnsResult.ips;

  // Check for DNS failure
  if (!dnsResult.success) {
    return {
      status: 'dns_failure',
      statusCode: null,
      responseTimeMs: dnsResult.responseTimeMs,
      error: `DNS resolution failed: ${dnsResult.error}`,
      isGeoBlocked: false,
      geoBlockingIndicators: [],
      detectionMetadata: null,
      dnsResponseTimeMs: dnsResult.responseTimeMs,
      dnsResolvedIps: [],
      region: PROBE_REGION
    };
  }

  // Check for DNS hijacking
  if (dnsResult.hijacked) {
    return {
      status: 'dns_failure',
      statusCode: null,
      responseTimeMs: dnsResult.responseTimeMs,
      error: `DNS hijacking detected: ${dnsResult.hijackReason}`,
      isGeoBlocked: false,
      geoBlockingIndicators: [],
      detectionMetadata: null,
      dnsResponseTimeMs: dnsResult.responseTimeMs,
      dnsResolvedIps: dnsResult.ips,
      region: PROBE_REGION
    };
  }

  console.log(`[DNS] Resolved ${hostname} to ${dnsResult.ips.join(', ')} in ${dnsResult.responseTimeMs}ms${dnsResult.cached ? ' (cached)' : ''}`);

  // Step 2: Perform HTTP check
  const httpStartTime = Date.now();

  return new Promise((resolve) => {
    try {
      const parsedUrl = new URL(url);
      const isHttps = parsedUrl.protocol === 'https:';
      const httpModule = isHttps ? https : http;

      // Get realistic browser headers
      const defaultHeaders = getHeadersObject('rotate');

      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: method,
        timeout: timeout,
        headers: {
          ...defaultHeaders,
          ...headers  // Custom headers override defaults
        },
        // Secure SSL validation: Even if ignoreSslErrors is true, hostname must match
        rejectUnauthorized: !config.ignoreSslErrors,
        checkServerIdentity: config.ignoreSslErrors ? (hostname, cert) => {
          // Custom validation when SSL errors are ignored
          // ALWAYS validate hostname to prevent MITM attacks
          const tls = require('tls');
          const hostnameCheck = tls.checkServerIdentity(hostname, cert);
          if (hostnameCheck) {
            // Hostname mismatch - reject even if ignoreSslErrors is true
            return hostnameCheck;
          }
          // Hostname matches - allow self-signed/expired certs
          return undefined;
        } : undefined
      };

      const req = httpModule.request(options, (res) => {
        let body = '';
        res.on('data', chunk => { body += chunk.toString().slice(0, 10000); }); // Limit body to 10KB
        res.on('end', () => {
          const httpResponseTime = Date.now() - httpStartTime;
          const totalResponseTime = httpResponseTime + dnsResponseTimeMs;
          const statusCode = res.statusCode;
          const isUp = statusCode === expectedStatus ||
                       (expectedStatus === 200 && statusCode >= 200 && statusCode < 300);

          // Extract response headers
          const responseHeaders = res.headers || {};

          // Enhanced geo-blocking detection
          const geoBlockDetection = detectGeoBlocking(
            statusCode,
            responseHeaders,
            body,
            httpResponseTime
          );

          // Check if response time exceeds degraded threshold (only if status is currently 'up')
          let status = isUp ? 'up' : 'down';
          let errorMsg = isUp ? null : `Expected ${expectedStatus}, got ${statusCode}`;

          // If geo-blocking detected, update error message
          if (geoBlockDetection.detected) {
            errorMsg = getBlockingMessage(geoBlockDetection);
          }

          if (status === 'up' && degradedThresholdMs && totalResponseTime > degradedThresholdMs) {
            status = 'degraded';
            errorMsg = `Response time ${totalResponseTime}ms exceeded threshold ${degradedThresholdMs}ms`;
          }

          // Build detection metadata
          let detectionMetadata = null;
          if (geoBlockDetection.detected) {
            detectionMetadata = {
              geoBlocking: geoBlockDetection,
              detectedAt: new Date().toISOString(),
            };
          }

          console.log(`[HTTP] ${status} - ${totalResponseTime}ms (DNS: ${dnsResponseTimeMs}ms, HTTP: ${httpResponseTime}ms)`);

          resolve({
            status,
            statusCode,
            responseTimeMs: totalResponseTime,
            error: errorMsg,
            // Legacy fields for backward compatibility
            isGeoBlocked: geoBlockDetection.detected || false,
            geoBlockingIndicators: geoBlockDetection.detected ? [geoBlockDetection.reason] : [],
            // New enhanced detection
            detectionMetadata,
            dnsResponseTimeMs,
            dnsResolvedIps,
            region: PROBE_REGION
          });
        });
      });

      req.on('error', (error) => {
        const httpResponseTime = Date.now() - httpStartTime;
        const totalResponseTime = httpResponseTime + dnsResponseTimeMs;

        // Try to detect geo-blocking from error message
        const geoBlockDetection = detectGeoBlocking(0, {}, error.message, httpResponseTime);

        let detectionMetadata = null;
        if (geoBlockDetection.detected) {
          detectionMetadata = {
            geoBlocking: geoBlockDetection,
            detectedAt: new Date().toISOString(),
          };
        }

        resolve({
          status: 'down',
          statusCode: 0,
          responseTimeMs: totalResponseTime,
          error: error.message,
          isGeoBlocked: geoBlockDetection.detected || false,
          geoBlockingIndicators: geoBlockDetection.detected ? [geoBlockDetection.reason] : [],
          detectionMetadata,
          dnsResponseTimeMs,
          dnsResolvedIps,
          region: PROBE_REGION
        });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({
          status: 'down',
          statusCode: 0,
          responseTimeMs: timeout + dnsResponseTimeMs,
          error: 'Request timeout',
          isGeoBlocked: false,
          geoBlockingIndicators: [],
          detectionMetadata: null,
          dnsResponseTimeMs,
          dnsResolvedIps,
          region: PROBE_REGION
        });
      });

      req.end();
    } catch (error) {
      const httpResponseTime = Date.now() - httpStartTime;
      const totalResponseTime = httpResponseTime + dnsResponseTimeMs;
      resolve({
        status: 'down',
        statusCode: 0,
        responseTimeMs: totalResponseTime,
        error: error.message,
        isGeoBlocked: false,
        geoBlockingIndicators: [],
        detectionMetadata: null,
        dnsResponseTimeMs,
        dnsResolvedIps,
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
