/**
 * Response Time Breakdown Module
 *
 * Provides detailed timing metrics for HTTP requests:
 * - DNS resolution time
 * - TCP connection time
 * - TLS handshake time (HTTPS only)
 * - Time to first byte (TTFB)
 * - Content download time
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

/**
 * Performs HTTP request with detailed timing breakdown
 * @param {string} url - Target URL
 * @param {object} options - Request options (method, headers, timeout, etc.)
 * @param {number} dnsTimeMs - DNS resolution time (measured separately)
 * @returns {Promise<object>} Response with timing breakdown
 */
async function performRequestWithTiming(url, options = {}, dnsTimeMs = 0) {
  return new Promise((resolve) => {
    const timings = {
      startTime: Date.now(),
      dnsMs: dnsTimeMs,
      tcpMs: null,
      tlsMs: null,
      ttfbMs: null,
      downloadMs: null,
      totalMs: null
    };

    try {
      const parsedUrl = new URL(url);
      const isHttps = parsedUrl.protocol === 'https:';
      const httpModule = isHttps ? https : http;

      const requestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: options.method || 'GET',
        timeout: options.timeout || 30000,
        headers: options.headers || {},
        rejectUnauthorized: options.rejectUnauthorized !== false
      };

      let socketAssignedTime = null;
      let tcpConnectedTime = null;
      let tlsConnectedTime = null;
      let firstByteTime = null;
      let downloadStartTime = null;

      const req = httpModule.request(requestOptions, (res) => {
        // Mark first byte received (TTFB)
        if (!firstByteTime) {
          firstByteTime = Date.now();
          timings.ttfbMs = firstByteTime - timings.startTime;
        }

        let body = '';
        let firstChunk = true;

        res.on('data', (chunk) => {
          if (firstChunk) {
            downloadStartTime = Date.now();
            firstChunk = false;
          }
          try {
            body += chunk.toString().slice(0, 10000); // Limit to 10KB
          } catch (e) {
            // Ignore chunk processing errors
          }
        });

        res.on('end', () => {
          const endTime = Date.now();

          // Calculate download time
          if (downloadStartTime) {
            timings.downloadMs = endTime - downloadStartTime;
          } else {
            timings.downloadMs = 0; // Empty response
          }

          // Total time (excluding DNS, which is measured separately)
          timings.totalMs = endTime - timings.startTime;

          resolve({
            success: true,
            statusCode: res.statusCode,
            headers: res.headers,
            body,
            timings
          });
        });
      });

      // Track socket assignment
      req.on('socket', (socket) => {
        socketAssignedTime = Date.now();

        // Socket already connected (reused from pool)
        if (socket.connecting === false) {
          tcpConnectedTime = socketAssignedTime;
          timings.tcpMs = 0; // Reused connection

          if (isHttps && socket.encrypted) {
            tlsConnectedTime = socketAssignedTime;
            timings.tlsMs = 0; // Reused TLS session
          }
        } else {
          // Track TCP connection
          socket.once('connect', () => {
            tcpConnectedTime = Date.now();
            timings.tcpMs = tcpConnectedTime - socketAssignedTime;
          });

          // Track TLS handshake (HTTPS only)
          if (isHttps) {
            socket.once('secureConnect', () => {
              tlsConnectedTime = Date.now();
              timings.tlsMs = tlsConnectedTime - (tcpConnectedTime || socketAssignedTime);
            });
          }
        }
      });

      req.on('error', (error) => {
        const endTime = Date.now();
        timings.totalMs = endTime - timings.startTime;

        resolve({
          success: false,
          error: error.message,
          statusCode: 0,
          timings
        });
      });

      req.on('timeout', () => {
        req.destroy();
        const endTime = Date.now();
        timings.totalMs = endTime - timings.startTime;

        resolve({
          success: false,
          error: 'Request timeout',
          statusCode: 0,
          timings
        });
      });

      req.end();
    } catch (error) {
      const endTime = Date.now();
      timings.totalMs = endTime - timings.startTime;

      resolve({
        success: false,
        error: error.message,
        statusCode: 0,
        timings
      });
    }
  });
}

module.exports = {
  performRequestWithTiming
};
