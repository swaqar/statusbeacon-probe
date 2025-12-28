/**
 * Cookie Jar Library
 *
 * Manages HTTP cookies for session-based monitoring
 * - Stores cookies per monitor
 * - Handles Set-Cookie parsing and Cookie header generation
 * - Auto-expires cookies based on Max-Age/Expires
 * - Domain and path matching
 */

const { CookieJar } = require('tough-cookie');

// In-memory cookie storage per monitor
const cookieStores = new Map();

// Default TTL: 1 hour
const DEFAULT_COOKIE_TTL = 3600 * 1000; // milliseconds

/**
 * Get or create cookie jar for a monitor
 */
function getCookieJar(monitorId, ttl = DEFAULT_COOKIE_TTL) {
  let store = cookieStores.get(monitorId);

  if (!store) {
    // Create new cookie jar
    store = {
      jar: new CookieJar(),
      lastUsed: Date.now(),
      ttl,
    };
    cookieStores.set(monitorId, store);
  } else {
    // Update last used timestamp
    store.lastUsed = Date.now();
  }

  return store.jar;
}

/**
 * Store cookies from Set-Cookie headers
 */
async function storeCookies(monitorId, url, setCookieHeaders, ttl) {
  const jar = getCookieJar(monitorId, ttl);

  // Normalize to array
  const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];

  for (const header of headers) {
    try {
      await jar.setCookie(header, url);
    } catch (error) {
      console.error(`[CookieJar] Failed to store cookie for ${monitorId}:`, error.message);
    }
  }
}

/**
 * Get Cookie header value for a request
 */
async function getCookieHeader(monitorId, url) {
  const store = cookieStores.get(monitorId);

  if (!store) {
    return null; // No cookies stored
  }

  try {
    const cookies = await store.jar.getCookies(url);
    if (cookies.length === 0) {
      return null;
    }

    // Format cookies as "Cookie: name1=value1; name2=value2"
    return cookies.map(c => `${c.key}=${c.value}`).join('; ');
  } catch (error) {
    console.error(`[CookieJar] Failed to get cookies for ${monitorId}:`, error.message);
    return null;
  }
}

/**
 * Clear all cookies for a monitor
 */
function clearCookies(monitorId) {
  cookieStores.delete(monitorId);
}

/**
 * Clear expired cookie stores (cleanup task)
 */
function cleanupExpiredStores() {
  const now = Date.now();
  const expired = [];

  for (const [monitorId, store] of cookieStores.entries()) {
    const age = now - store.lastUsed;
    if (age > store.ttl) {
      expired.push(monitorId);
    }
  }

  for (const monitorId of expired) {
    cookieStores.delete(monitorId);
  }

  if (expired.length > 0) {
    console.log(`[CookieJar] Cleaned up ${expired.length} expired cookie stores`);
  }
}

/**
 * Get cookie jar statistics
 */
function getCookieStats() {
  const now = Date.now();
  const stores = [];

  for (const [monitorId, store] of cookieStores.entries()) {
    stores.push({
      monitorId,
      cookieCount: -1, // Unknown (async only)
      age: now - store.lastUsed,
    });
  }

  return {
    totalStores: cookieStores.size,
    stores,
  };
}

module.exports = {
  getCookieJar,
  storeCookies,
  getCookieHeader,
  clearCookies,
  cleanupExpiredStores,
  getCookieStats,
};
