/**
 * Redirect Chain Tracking for StatusBeacon Probe
 *
 * Manually follows HTTP redirects and tracks the full chain:
 * - Each hop's URL, status code, and timing
 * - Final destination URL
 * - Detects redirect loops
 * - Detects geo-based redirects
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

const REDIRECT_STATUS_CODES = [301, 302, 303, 307, 308];
const MAX_REDIRECTS = 10;

/**
 * Follows redirects manually and tracks the full chain
 * @param {string} initialUrl - Starting URL
 * @param {object} options - Request options (method, headers, timeout, etc.)
 * @param {number} maxRedirects - Maximum redirects to follow (default 10)
 * @returns {Promise<object>} Redirect chain data
 */
async function followRedirects(initialUrl, options = {}, maxRedirects = MAX_REDIRECTS) {
  const redirectChain = [];
  const visitedUrls = new Set();
  let currentUrl = initialUrl;
  let redirectCount = 0;
  let totalTime = 0;

  while (redirectCount < maxRedirects) {
    // Detect redirect loop
    if (visitedUrls.has(currentUrl)) {
      return {
        redirectCount,
        finalUrl: currentUrl,
        redirectChain,
        isLoop: true,
        loopDetectedAt: currentUrl,
        totalRedirectTime: totalTime
      };
    }

    visitedUrls.add(currentUrl);

    // Perform single HTTP request (no auto-redirect)
    const hopResult = await performSingleRequest(currentUrl, {
      ...options,
      followRedirects: false // Disable auto-redirect
    });

    const hop = {
      url: currentUrl,
      statusCode: hopResult.statusCode,
      location: hopResult.location,
      responseTimeMs: hopResult.responseTimeMs,
      headers: hopResult.headers
    };

    redirectChain.push(hop);
    totalTime += hopResult.responseTimeMs;

    // If not a redirect, we've reached the final destination
    if (!REDIRECT_STATUS_CODES.includes(hopResult.statusCode)) {
      return {
        redirectCount,
        finalUrl: currentUrl,
        redirectChain,
        isLoop: false,
        totalRedirectTime: totalTime,
        finalStatusCode: hopResult.statusCode,
        finalResponse: hopResult
      };
    }

    // Check if Location header exists
    if (!hopResult.location) {
      // No Location header - this is the final response (likely JS redirect or Cloudflare challenge)
      // Return the current response as finalResponse so the probe can analyze it
      return {
        redirectCount,
        finalUrl: currentUrl,
        redirectChain,
        isLoop: false,
        totalRedirectTime: totalTime,
        finalStatusCode: hopResult.statusCode,
        finalResponse: hopResult,
        noLocationHeader: true, // Flag to indicate this was a redirect without Location
        error: `Redirect status ${hopResult.statusCode} but no Location header`
      };
    }

    // Follow redirect
    currentUrl = resolveRedirectUrl(currentUrl, hopResult.location);
    redirectCount++;
  }

  // Max redirects exceeded
  return {
    redirectCount,
    finalUrl: currentUrl,
    redirectChain,
    isLoop: false,
    maxRedirectsExceeded: true,
    totalRedirectTime: totalTime,
    error: `Maximum redirects (${maxRedirects}) exceeded`
  };
}

/**
 * Performs a single HTTP request without following redirects
 */
function performSingleRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();

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
        rejectUnauthorized: options.rejectUnauthorized !== false,
        // Disable auto-redirect (Node.js doesn't auto-redirect by default, but explicit)
        followRedirect: false,
        maxRedirects: 0
      };

      const req = httpModule.request(requestOptions, (res) => {
        const responseTimeMs = Date.now() - startTime;

        // Don't read body for redirects (waste of bandwidth)
        if (REDIRECT_STATUS_CODES.includes(res.statusCode)) {
          res.resume(); // Drain response to free memory
          resolve({
            statusCode: res.statusCode,
            location: res.headers.location,
            headers: res.headers,
            responseTimeMs
          });
        } else {
          // Read body for final response
          let body = '';
          res.on('data', chunk => {
            body += chunk.toString().slice(0, 10000); // Limit to 10KB
          });
          res.on('end', () => {
            resolve({
              statusCode: res.statusCode,
              location: res.headers.location,
              headers: res.headers,
              body,
              responseTimeMs
            });
          });
        }
      });

      req.on('error', (error) => {
        resolve({
          statusCode: 0,
          error: error.message,
          responseTimeMs: Date.now() - startTime
        });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({
          statusCode: 0,
          error: 'Request timeout',
          responseTimeMs: options.timeout || 30000
        });
      });

      req.end();
    } catch (error) {
      resolve({
        statusCode: 0,
        error: error.message,
        responseTimeMs: Date.now() - startTime
      });
    }
  });
}

/**
 * Resolves relative or absolute redirect URLs
 */
function resolveRedirectUrl(currentUrl, location) {
  try {
    // If location is absolute, use it directly
    if (location.startsWith('http://') || location.startsWith('https://')) {
      return location;
    }

    // If location is protocol-relative (//example.com/path)
    if (location.startsWith('//')) {
      const currentParsed = new URL(currentUrl);
      return `${currentParsed.protocol}${location}`;
    }

    // Otherwise, resolve relative to current URL
    const base = new URL(currentUrl);
    const resolved = new URL(location, base);
    return resolved.href;
  } catch (error) {
    // Fallback: return location as-is
    return location;
  }
}

/**
 * Detects geo-based redirects by analyzing the redirect chain
 */
function detectGeoRedirect(redirectChain) {
  if (!redirectChain || redirectChain.length === 0) {
    return { detected: false };
  }

  const geoPatterns = [
    /\/[a-z]{2}(-[a-z]{2})?\//i,  // /en-us/, /uk/, /de/, etc.
    /\/(en|de|fr|es|it|pt|ja|zh|ko|ru|ar)\//i,  // Language codes
    /country=/i,
    /region=/i,
    /locale=/i,
    /lang=/i
  ];

  for (let i = 0; i < redirectChain.length; i++) {
    const hop = redirectChain[i];

    // Check if redirect URL contains geo patterns
    if (hop.location) {
      for (const pattern of geoPatterns) {
        if (pattern.test(hop.location)) {
          return {
            detected: true,
            reason: 'Geo-based redirect detected',
            pattern: pattern.toString(),
            redirectUrl: hop.location,
            hopIndex: i
          };
        }
      }
    }
  }

  return { detected: false };
}

module.exports = {
  followRedirects,
  detectGeoRedirect,
  REDIRECT_STATUS_CODES,
  MAX_REDIRECTS
};
