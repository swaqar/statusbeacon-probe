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
const { getCookieHeader, storeCookies } = require('./cookieJar');
const { followRedirects, detectGeoRedirect, REDIRECT_STATUS_CODES } = require('./redirectTracking');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3002;
const PROBE_SECRET = process.env.PROBE_SECRET || '';
const PROBE_REGION = process.env.PROBE_REGION || 'unknown';

// Catch unhandled errors at process level (suppress ECONNRESET during cleanup)
process.on('uncaughtException', (error) => {
  // Ignore ECONNRESET errors - these are socket cleanup errors after successful response
  if (error.code === 'ECONNRESET') {
    return; // Suppress - this is harmless
  }
  console.error('[FATAL] Uncaught Exception:', {
    message: error.message,
    code: error.code,
    stack: error.stack
  });
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[FATAL] Unhandled Rejection:', {
    reason: reason,
    promise: promise
  });
});

// Perform HTTP check
async function performHttpCheck(config) {
  const { url, method = 'GET', expectedStatus = 200, timeout = 30000, headers = {}, degradedThresholdMs, monitorId, enableCookies, cookieTtlSeconds } = config;

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
      redirectCount: 0,
      finalUrl: url,
      redirectChain: null,
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
      redirectCount: 0,
      finalUrl: url,
      redirectChain: null,
      region: PROBE_REGION
    };
  }

  console.log(`[DNS] Resolved ${hostname} to ${dnsResult.ips.join(', ')} in ${dnsResult.responseTimeMs}ms${dnsResult.cached ? ' (cached)' : ''}`);

  // Step 2: Get cookies if enabled (before HTTP check)
  let cookieHeaderValue = null;
  if (enableCookies && monitorId) {
    cookieHeaderValue = await getCookieHeader(monitorId, url);
    if (cookieHeaderValue) {
      console.log(`[CookieJar] Sending ${cookieHeaderValue.split(';').length} cookie(s) for monitor ${monitorId}`);
    }
  }

  // Step 3: Perform HTTP check
  const httpStartTime = Date.now();

  return new Promise((resolve) => {
    let resolved = false;
    const safeResolve = (result) => {
      if (!resolved) {
        resolved = true;
        resolve(result);
      }
    };

    try {
      // Parse URL first (can throw)
      const parsedUrl = new URL(url);
      const isHttps = parsedUrl.protocol === 'https:';
      const httpModule = isHttps ? https : http;

      // Get realistic browser headers
      const defaultHeaders = getHeadersObject('rotate');

      // Prepare request headers
      const requestHeaders = {
        ...defaultHeaders,
        ...headers  // Custom headers override defaults
      };

      // Add cookies if we have them
      if (cookieHeaderValue) {
        requestHeaders['Cookie'] = cookieHeaderValue;
      }

      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: method,
        timeout: timeout,
        headers: requestHeaders,
        rejectUnauthorized: !config.ignoreSslErrors
        // Note: checkServerIdentity removed - causes ECONNRESET errors with some servers
      };

      // Note: HTTP/2 is disabled via NODE_NO_HTTP2=1 environment variable set in systemd service

      const req = httpModule.request(options, (res) => {
        // Handle socket errors during response processing
        if (res.socket) {
          res.socket.on('error', (socketError) => {
            // Suppress - these are cleanup errors after successful response
          });
        }

        let body = '';
        res.on('data', chunk => {
          try {
            body += chunk.toString().slice(0, 10000); // Limit body to 10KB
          } catch (e) {
            console.error('[HTTP] Error processing response chunk:', e.message);
          }
        });
        res.on('end', async () => {
          try {
            const httpResponseTime = Date.now() - httpStartTime;
            const totalResponseTime = httpResponseTime + dnsResponseTimeMs;
            const statusCode = res.statusCode;
            const isUp = statusCode === expectedStatus ||
                         (expectedStatus === 200 && statusCode >= 200 && statusCode < 300);

            // Extract response headers
            const responseHeaders = res.headers || {};

            // Store cookies if enabled
            if (enableCookies && monitorId && responseHeaders['set-cookie']) {
              const setCookieHeaders = responseHeaders['set-cookie'];
              const ttl = cookieTtlSeconds ? cookieTtlSeconds * 1000 : undefined;
              storeCookies(monitorId, url, setCookieHeaders, ttl).then(() => {
                console.log(`[CookieJar] Stored ${Array.isArray(setCookieHeaders) ? setCookieHeaders.length : 1} cookie(s) for monitor ${monitorId}`);
              }).catch((error) => {
                console.error(`[CookieJar] Failed to store cookies for monitor ${monitorId}:`, error.message);
              });
            }

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

            // Redirect tracking: Check if this is a redirect response
            let redirectCount = 0;
            let finalUrl = url;
            let redirectChain = null;

            if (REDIRECT_STATUS_CODES.includes(statusCode) && responseHeaders.location) {
              console.log(`[Redirect] Detected ${statusCode} redirect to ${responseHeaders.location}`);

              // Build initial hop
              const initialHop = {
                url: url,
                statusCode: statusCode,
                location: responseHeaders.location,
                responseTimeMs: httpResponseTime
              };

              // Follow the redirect chain
              try {
                const redirectResult = await followRedirects(url, {
                  method,
                  headers: requestHeaders,
                  timeout,
                  rejectUnauthorized: !config.ignoreSslErrors
                });

                redirectCount = redirectResult.redirectCount;
                finalUrl = redirectResult.finalUrl;
                redirectChain = redirectResult.redirectChain;

                // Check for geo-based redirects
                const geoRedirect = detectGeoRedirect(redirectChain);
                if (geoRedirect.detected) {
                  console.log(`[Redirect] Geo-based redirect detected: ${geoRedirect.reason}`);
                  if (!detectionMetadata) {
                    detectionMetadata = {};
                  }
                  detectionMetadata.geoRedirect = geoRedirect;
                }

                // Log redirect chain
                console.log(`[Redirect] Followed ${redirectCount} redirect(s), final URL: ${finalUrl}`);
              } catch (redirectError) {
                console.error(`[Redirect] Error following redirects: ${redirectError.message}`);
              }
            }

            console.log(`[HTTP] ${status} - ${totalResponseTime}ms (DNS: ${dnsResponseTimeMs}ms, HTTP: ${httpResponseTime}ms)`);

            safeResolve({
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
              // Redirect tracking
              redirectCount,
              finalUrl,
              redirectChain,
              region: PROBE_REGION
            });
          } catch (endError) {
            console.error('[HTTP] Error in end handler:', endError.message);
            safeResolve({
              status: 'down',
              statusCode: 0,
              responseTimeMs: Date.now() - httpStartTime + dnsResponseTimeMs,
              error: `Response processing error: ${endError.message}`,
              isGeoBlocked: false,
              geoBlockingIndicators: [],
              detectionMetadata: null,
              dnsResponseTimeMs,
              dnsResolvedIps,
              redirectCount: 0,
              finalUrl: url,
              redirectChain: null,
              region: PROBE_REGION
            });
          }
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

        safeResolve({
          status: 'down',
          statusCode: 0,
          responseTimeMs: totalResponseTime,
          error: error.message,
          isGeoBlocked: geoBlockDetection.detected || false,
          geoBlockingIndicators: geoBlockDetection.detected ? [geoBlockDetection.reason] : [],
          detectionMetadata,
          dnsResponseTimeMs,
          dnsResolvedIps,
          redirectCount: 0,
          finalUrl: url,
          redirectChain: null,
          region: PROBE_REGION
        });
      });

      req.on('timeout', () => {
        req.destroy();
        safeResolve({
          status: 'down',
          statusCode: 0,
          responseTimeMs: timeout + dnsResponseTimeMs,
          error: 'Request timeout',
          isGeoBlocked: false,
          geoBlockingIndicators: [],
          detectionMetadata: null,
          dnsResponseTimeMs,
          dnsResolvedIps,
          redirectCount: 0,
          finalUrl: url,
          redirectChain: null,
          region: PROBE_REGION
        });
      });

      // Handle socket-level errors that occur during connection/cleanup
      req.on('socket', (socket) => {
        socket.on('error', (socketError) => {
          // Suppress - these are handled by req.on('error')
        });
      });

      try {
        req.end();
      } catch (endError) {
        safeResolve({
          status: 'down',
          statusCode: 0,
          responseTimeMs: Date.now() - httpStartTime + dnsResponseTimeMs,
          error: `req.end() error: ${endError.message}`,
          isGeoBlocked: false,
          geoBlockingIndicators: [],
          detectionMetadata: null,
          dnsResponseTimeMs,
          dnsResolvedIps,
          redirectCount: 0,
          finalUrl: url,
          redirectChain: null,
          region: PROBE_REGION
        });
      }
    } catch (error) {
      const httpResponseTime = Date.now() - httpStartTime;
      const totalResponseTime = httpResponseTime + dnsResponseTimeMs;
      safeResolve({
        status: 'down',
        statusCode: 0,
        responseTimeMs: totalResponseTime,
        error: error.message,
        isGeoBlocked: false,
        geoBlockingIndicators: [],
        detectionMetadata: null,
        dnsResponseTimeMs,
        dnsResolvedIps,
        redirectCount: 0,
        finalUrl: url,
        redirectChain: null,
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
    const { url, method, expectedStatus, timeout, headers, ignoreSslErrors, degradedThresholdMs, monitorType, host, port, monitorId, enableCookies, cookieTtlSeconds } = req.body;

    let result;

    if (monitorType === 'tcp' || (!url && host && port)) {
      result = await performTcpCheck({ host, port, timeout, degradedThresholdMs });
    } else if (url) {
      result = await performHttpCheck({ url, method, expectedStatus, timeout, headers, ignoreSslErrors, degradedThresholdMs, monitorId, enableCookies, cookieTtlSeconds });
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
