/**
 * Enhanced Geo-Blocking Detection Library (JavaScript version for probe)
 *
 * Detects various types of geo-blocking, WAF blocks, and CDN challenges
 * Used by probe service for distributed monitoring
 */

// Expanded status codes that indicate blocking
const GEO_BLOCKING_STATUS_CODES = [
  403, // Forbidden
  451, // Unavailable For Legal Reasons (official geo-blocking code)
  406, // Not Acceptable
  402, // Payment Required (sometimes used for regional restrictions)
  410, // Gone (sometimes used for geo-blocked content)
  418, // I'm a teapot (some WAFs use this)
  429, // Too Many Requests (rate limiting)
  503, // Service Unavailable (sometimes with geo-blocking)
];

// Keywords that indicate geo-blocking
const GEO_BLOCKING_KEYWORDS = [
  // General geo-blocking
  'geo-block',
  'geoblocked',
  'geo block',
  'not available in your country',
  'not available in your region',
  'not available in your location',
  'content is not available',
  'access denied',
  'access restricted',
  'region restricted',
  'country restricted',
  'location restricted',
  'territory restricted',
  'geographical restriction',
  'geographic restriction',

  // Legal/compliance
  'legal reasons',
  'regulatory reasons',
  'compliance reasons',
  'gdpr',

  // Blocking messages
  'forbidden',
  'blocked',
  'not permitted',
  'unavailable',
];

// Cloudflare-specific patterns
const CLOUDFLARE_PATTERNS = [
  'cloudflare',
  'cf-ray',
  'attention required',
  'checking your browser',
  'just a moment',
  'please wait',
  'cf-challenge',
  'cf-captcha',
  '__cf_bm',
  'cf_clearance',
];

// WAF provider patterns
const WAF_PATTERNS = {
  cloudflare: ['cloudflare', 'cf-ray'],
  imperva: ['imperva', 'incapsula', '_incap_'],
  akamai: ['akamai', 'reference #'],
  aws_waf: ['aws waf', 'awswaf'],
  f5: ['f5', 'bigip'],
  barracuda: ['barracuda'],
  sucuri: ['sucuri', 'access denied - sucuri'],
  wordfence: ['wordfence', 'access from your location has been blocked'],
};

// Rate limiting indicators
const RATE_LIMIT_PATTERNS = [
  'rate limit',
  'too many requests',
  'quota exceeded',
  'request limit',
  'throttled',
  'slow down',
];

/**
 * Detect geo-blocking from status code, headers, and response body
 */
function detectGeoBlocking(statusCode, headers, responseBody, responseTime) {
  const bodyLower = responseBody.toLowerCase();
  const headersLower = {};

  // Normalize headers to lowercase
  for (const [key, value] of Object.entries(headers)) {
    headersLower[key.toLowerCase()] = Array.isArray(value) ? value.join(' ').toLowerCase() : value.toLowerCase();
  }

  // 1. Check for Cloudflare challenges/blocks
  const cloudflareDetection = detectCloudflare(statusCode, headersLower, bodyLower);
  if (cloudflareDetection.detected) {
    return cloudflareDetection;
  }

  // 2. Check for WAF blocks
  const wafDetection = detectWAF(statusCode, headersLower, bodyLower);
  if (wafDetection.detected) {
    return wafDetection;
  }

  // 3. Check for rate limiting
  const rateLimitDetection = detectRateLimit(statusCode, headersLower, bodyLower);
  if (rateLimitDetection.detected) {
    return rateLimitDetection;
  }

  // 4. Check for general geo-blocking
  const geoDetection = detectGeneralGeoBlocking(statusCode, headersLower, bodyLower, responseTime);
  if (geoDetection.detected) {
    return geoDetection;
  }

  return { detected: false };
}

/**
 * Detect Cloudflare challenges and blocks
 */
function detectCloudflare(statusCode, headers, body) {
  const cfRay = headers['cf-ray'];
  const server = headers['server'];
  const isCloudflare = server?.includes('cloudflare') || cfRay !== undefined;

  if (!isCloudflare) {
    return { detected: false };
  }

  // Check for Cloudflare challenge
  for (const pattern of CLOUDFLARE_PATTERNS) {
    if (body.includes(pattern)) {
      // Determine challenge type
      let challengeType = 'unknown';
      if (body.includes('cf-captcha') || body.includes('captcha')) {
        challengeType = 'CAPTCHA';
      } else if (body.includes('cf-challenge') || body.includes('checking your browser')) {
        challengeType = 'JavaScript Challenge';
      } else if (body.includes('just a moment') || body.includes('please wait')) {
        challengeType = 'Managed Challenge';
      }

      return {
        detected: true,
        reason: `Cloudflare ${challengeType} detected`,
        type: 'cloudflare',
        metadata: {
          statusCode,
          cfRay,
          wafProvider: 'Cloudflare',
        },
      };
    }
  }

  // Cloudflare 403 without challenge = likely geo-block or firewall rule
  if (statusCode === 403) {
    return {
      detected: true,
      reason: 'Cloudflare firewall block (possible geo-restriction)',
      type: 'cloudflare',
      metadata: {
        statusCode,
        cfRay,
        wafProvider: 'Cloudflare',
      },
    };
  }

  return { detected: false };
}

/**
 * Detect WAF blocks
 */
function detectWAF(statusCode, headers, body) {
  if (!GEO_BLOCKING_STATUS_CODES.includes(statusCode)) {
    return { detected: false };
  }

  // Check each WAF provider
  for (const [provider, patterns] of Object.entries(WAF_PATTERNS)) {
    for (const pattern of patterns) {
      if (body.includes(pattern) || Object.values(headers).some(h => h.includes(pattern))) {
        return {
          detected: true,
          reason: `WAF block detected (${provider})`,
          type: 'waf',
          metadata: {
            statusCode,
            wafProvider: provider,
          },
        };
      }
    }
  }

  return { detected: false };
}

/**
 * Detect rate limiting
 */
function detectRateLimit(statusCode, headers, body) {
  // 429 is the standard rate limit code
  if (statusCode === 429) {
    return {
      detected: true,
      reason: 'Rate limit exceeded (HTTP 429)',
      type: 'rate_limit',
      metadata: {
        statusCode,
      },
    };
  }

  // Check for rate limit patterns in body
  for (const pattern of RATE_LIMIT_PATTERNS) {
    if (body.includes(pattern)) {
      return {
        detected: true,
        reason: `Rate limit detected: ${pattern}`,
        type: 'rate_limit',
        metadata: {
          statusCode,
        },
      };
    }
  }

  // Check rate limit headers
  if (headers['x-ratelimit-remaining'] === '0' || headers['retry-after']) {
    return {
      detected: true,
      reason: 'Rate limit headers detected',
      type: 'rate_limit',
      metadata: {
        statusCode,
      },
    };
  }

  return { detected: false };
}

/**
 * Detect general geo-blocking
 */
function detectGeneralGeoBlocking(statusCode, headers, body, responseTime) {
  // Check status code
  if (!GEO_BLOCKING_STATUS_CODES.includes(statusCode)) {
    return { detected: false };
  }

  // Check for geo-blocking keywords in body
  for (const keyword of GEO_BLOCKING_KEYWORDS) {
    if (body.includes(keyword)) {
      return {
        detected: true,
        reason: `Geo-blocking detected: "${keyword}" found in response`,
        type: 'geo_blocking',
        metadata: {
          statusCode,
          responseTime,
        },
      };
    }
  }

  // Check for geo-blocking headers
  if (headers['x-geo-block'] || headers['x-country-block']) {
    return {
      detected: true,
      reason: 'Geo-blocking header detected',
      type: 'geo_blocking',
      metadata: {
        statusCode,
      },
    };
  }

  // REMOVED: Fast 403 heuristic - too many false positives from bot detection, WAF, auth failures
  // Only flag as geo-blocking if there's explicit evidence (keywords/headers above)

  return { detected: false };
}

/**
 * Get a user-friendly message for detected blocking
 */
function getBlockingMessage(detection) {
  if (!detection.detected) {
    return '';
  }

  const { type, reason, metadata } = detection;

  switch (type) {
    case 'cloudflare':
      return `Cloudflare Protection: ${reason}${metadata?.cfRay ? ` (Ray ID: ${metadata.cfRay})` : ''}`;

    case 'waf':
      return `WAF Block: ${reason}`;

    case 'rate_limit':
      return `Rate Limited: ${reason}`;

    case 'geo_blocking':
      return `Geo-Blocked: ${reason}`;

    case 'challenge':
      return `Challenge Required: ${reason}`;

    default:
      return reason;
  }
}

module.exports = {
  detectGeoBlocking,
  getBlockingMessage,
};
