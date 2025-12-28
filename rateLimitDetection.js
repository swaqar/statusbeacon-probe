/**
 * Rate Limit Detection Module
 *
 * Detects and parses rate limiting responses from HTTP endpoints.
 * Supports:
 * - 429 Too Many Requests
 * - 503 Service Unavailable (rate limit variant)
 * - Retry-After header (seconds or HTTP date)
 * - X-RateLimit-* headers (GitHub, Stripe, etc.)
 */

const RATE_LIMIT_STATUS_CODES = [429, 503];

const RATE_LIMIT_BODY_PATTERNS = [
  'rate limit',
  'too many requests',
  'quota exceeded',
  'rate exceeded',
  'throttle',
  'slowdown'
];

/**
 * Detect if response indicates rate limiting
 * @param {number} statusCode - HTTP status code
 * @param {object} headers - Response headers
 * @param {string} body - Response body (first 1KB)
 * @returns {object} Rate limit detection result
 */
function detectRateLimit(statusCode, headers, body = '') {
  // Quick status code check
  if (!RATE_LIMIT_STATUS_CODES.includes(statusCode)) {
    // Check 503 with rate limit indicators
    if (statusCode === 503) {
      const bodyLower = body.toLowerCase();
      const hasRateLimitPattern = RATE_LIMIT_BODY_PATTERNS.some(pattern =>
        bodyLower.includes(pattern)
      );

      if (!hasRateLimitPattern) {
        return { detected: false };
      }
    } else {
      return { detected: false };
    }
  }

  // Parse headers
  const rateLimitInfo = parseRateLimitHeaders(headers);

  // Check body for rate limit patterns (if status is 429)
  if (statusCode === 429 || statusCode === 503) {
    const bodyLower = body.toLowerCase();
    for (const pattern of RATE_LIMIT_BODY_PATTERNS) {
      if (bodyLower.includes(pattern)) {
        return {
          detected: true,
          statusCode,
          type: statusCode === 429 ? '429_too_many_requests' : '503_rate_limit',
          retryAfter: rateLimitInfo.retryAfter,
          limit: rateLimitInfo.limit,
          remaining: rateLimitInfo.remaining,
          reset: rateLimitInfo.reset,
          resetDate: rateLimitInfo.resetDate,
          pattern
        };
      }
    }
  }

  // If we have retry-after or rate limit headers, it's a rate limit
  if (rateLimitInfo.retryAfter || rateLimitInfo.limit !== null) {
    return {
      detected: true,
      statusCode,
      type: statusCode === 429 ? '429_too_many_requests' : '503_rate_limit',
      ...rateLimitInfo
    };
  }

  return { detected: false };
}

/**
 * Parse rate limit headers
 * Supports multiple header formats:
 * - Retry-After (standard)
 * - X-RateLimit-* (GitHub, Stripe style)
 * - X-Rate-Limit-* (alternative)
 * - RateLimit-* (new standard)
 *
 * @param {object} headers - Response headers
 * @returns {object} Parsed rate limit information
 */
function parseRateLimitHeaders(headers) {
  const result = {
    retryAfter: null,      // Seconds to wait
    limit: null,           // Total requests allowed
    remaining: null,       // Requests remaining
    reset: null,           // Reset timestamp (Unix epoch)
    resetDate: null        // Reset date (ISO string)
  };

  // Normalize headers to lowercase
  const normalizedHeaders = {};
  for (const [key, value] of Object.entries(headers)) {
    normalizedHeaders[key.toLowerCase()] = value;
  }

  // 1. Parse Retry-After (standard header)
  const retryAfter = normalizedHeaders['retry-after'];
  if (retryAfter) {
    // Can be seconds (number) or HTTP date
    const secondsMatch = /^(\d+)$/.exec(retryAfter);
    if (secondsMatch) {
      result.retryAfter = parseInt(secondsMatch[1], 10);
    } else {
      // HTTP date format
      try {
        const retryDate = new Date(retryAfter);
        const now = new Date();
        result.retryAfter = Math.max(0, Math.ceil((retryDate - now) / 1000));
      } catch (e) {
        // Invalid date, ignore
      }
    }
  }

  // 2. Parse X-RateLimit-* headers (GitHub, Stripe, etc.)
  const rateLimitLimit =
    normalizedHeaders['x-ratelimit-limit'] ||
    normalizedHeaders['x-rate-limit-limit'] ||
    normalizedHeaders['ratelimit-limit'];

  const rateLimitRemaining =
    normalizedHeaders['x-ratelimit-remaining'] ||
    normalizedHeaders['x-rate-limit-remaining'] ||
    normalizedHeaders['ratelimit-remaining'];

  const rateLimitReset =
    normalizedHeaders['x-ratelimit-reset'] ||
    normalizedHeaders['x-rate-limit-reset'] ||
    normalizedHeaders['ratelimit-reset'];

  if (rateLimitLimit) {
    result.limit = parseInt(rateLimitLimit, 10);
  }

  if (rateLimitRemaining) {
    result.remaining = parseInt(rateLimitRemaining, 10);
  }

  if (rateLimitReset) {
    result.reset = parseInt(rateLimitReset, 10);

    // Convert to ISO date
    try {
      result.resetDate = new Date(result.reset * 1000).toISOString();

      // Calculate retry-after if not already set
      if (!result.retryAfter) {
        const now = Math.floor(Date.now() / 1000);
        result.retryAfter = Math.max(0, result.reset - now);
      }
    } catch (e) {
      // Invalid timestamp
    }
  }

  return result;
}

/**
 * Calculate next check time based on rate limit info
 * @param {object} rateLimitInfo - Detected rate limit info
 * @param {number} currentInterval - Current check interval (seconds)
 * @returns {object} Recommended backoff settings
 */
function calculateBackoff(rateLimitInfo, currentInterval, consecutiveRateLimits = 0) {
  let backoffSeconds = currentInterval;

  if (rateLimitInfo.retryAfter) {
    // Use Retry-After header value
    backoffSeconds = rateLimitInfo.retryAfter;
  } else {
    // Exponential backoff: 1min → 2min → 5min → 10min → 20min (max)
    const backoffLevels = [60, 120, 300, 600, 1200];
    const level = Math.min(consecutiveRateLimits, backoffLevels.length - 1);
    backoffSeconds = backoffLevels[level];
  }

  // Cap at 1 hour
  backoffSeconds = Math.min(backoffSeconds, 3600);

  // Don't go below original interval
  backoffSeconds = Math.max(backoffSeconds, currentInterval);

  return {
    backoffSeconds,
    nextCheckAt: new Date(Date.now() + backoffSeconds * 1000).toISOString(),
    shouldIncreaseInterval: consecutiveRateLimits >= 2,  // After 2 consecutive, increase base interval
    recommendedInterval: consecutiveRateLimits >= 2 ? Math.min(currentInterval * 2, 600) : currentInterval
  };
}

module.exports = {
  detectRateLimit,
  parseRateLimitHeaders,
  calculateBackoff,
  RATE_LIMIT_STATUS_CODES
};
