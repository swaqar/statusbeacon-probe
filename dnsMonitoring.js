/**
 * DNS Monitoring Library (Probe Version)
 *
 * Performs DNS resolution monitoring to separate DNS failures from HTTP/TCP failures
 * Includes DNS hijacking detection, caching, and performance measurement
 */

const dns = require('dns');
const { promisify } = require('util');

const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);

// DNS cache to reduce queries (60 second TTL)
const dnsCache = new Map();
const DNS_CACHE_TTL = 60000; // 60 seconds

// Known DNS hijacking / sinkhole IPs
const KNOWN_HIJACK_IPS = [
  '0.0.0.0',
  '127.0.0.1',
  '127.0.0.53',
  '::1',
  '198.105.244.11', // Cox redirect
  '198.105.254.11',
];

/**
 * Check if DNS result appears to be hijacked
 */
function detectDnsHijacking(hostname, ips) {
  // Check for known hijack IPs
  for (const ip of ips) {
    if (KNOWN_HIJACK_IPS.includes(ip)) {
      return {
        hijacked: true,
        reason: `DNS returned known sinkhole IP: ${ip}`,
      };
    }
  }

  // Check for localhost/loopback (should never be returned for external domains)
  if (!hostname.includes('localhost') && !hostname.includes('127.0.0.1')) {
    for (const ip of ips) {
      if (ip.startsWith('127.') || ip === '::1') {
        return {
          hijacked: true,
          reason: `DNS returned localhost IP for external domain: ${ip}`,
        };
      }
    }
  }

  // Check for private IPs on public domains (suspicious)
  const isPrivateIp = (ip) => {
    return (
      ip.startsWith('10.') ||
      ip.startsWith('172.16.') ||
      ip.startsWith('172.17.') ||
      ip.startsWith('172.18.') ||
      ip.startsWith('172.19.') ||
      ip.startsWith('172.20.') ||
      ip.startsWith('172.21.') ||
      ip.startsWith('172.22.') ||
      ip.startsWith('172.23.') ||
      ip.startsWith('172.24.') ||
      ip.startsWith('172.25.') ||
      ip.startsWith('172.26.') ||
      ip.startsWith('172.27.') ||
      ip.startsWith('172.28.') ||
      ip.startsWith('172.29.') ||
      ip.startsWith('172.30.') ||
      ip.startsWith('172.31.') ||
      ip.startsWith('192.168.') ||
      ip.startsWith('169.254.') // Link-local
    );
  };

  // Only flag private IPs as suspicious for well-known public domains
  const publicDomains = ['google.com', 'cloudflare.com', 'amazon.com', 'microsoft.com', 'apple.com'];
  if (publicDomains.some(domain => hostname.includes(domain))) {
    for (const ip of ips) {
      if (isPrivateIp(ip)) {
        return {
          hijacked: true,
          reason: `DNS returned private IP for public domain: ${ip}`,
        };
      }
    }
  }

  return { hijacked: false };
}

/**
 * Get cached DNS result if available and not expired
 */
function getCachedDns(hostname) {
  const cached = dnsCache.get(hostname);
  if (!cached) {
    return null;
  }

  const age = Date.now() - cached.timestamp;
  if (age > cached.ttl) {
    dnsCache.delete(hostname);
    return null;
  }

  return cached.ips;
}

/**
 * Cache DNS result
 */
function cacheDnsResult(hostname, ips, ttl = DNS_CACHE_TTL) {
  dnsCache.set(hostname, {
    ips,
    timestamp: Date.now(),
    ttl,
  });
}

/**
 * Perform DNS lookup with timeout
 */
async function resolveDnsWithTimeout(hostname, timeout, ipVersion = 4) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`DNS timeout after ${timeout}ms`));
    }, timeout);

    const resolveFunc = ipVersion === 4 ? resolve4 : resolve6;

    resolveFunc(hostname)
      .then(ips => {
        clearTimeout(timer);
        resolve(ips);
      })
      .catch(err => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

/**
 * Resolve DNS with monitoring
 *
 * @param {string} hostname - Hostname to resolve
 * @param {number} timeout - DNS timeout in milliseconds (default: 5000ms)
 * @param {boolean} useCache - Whether to use cached results (default: true)
 * @returns {Promise<Object>} DNS resolution result with timing and hijacking detection
 */
async function resolveDns(hostname, timeout = 5000, useCache = true) {
  const startTime = Date.now();

  // Check cache first
  if (useCache) {
    const cachedIps = getCachedDns(hostname);
    if (cachedIps) {
      const hijackCheck = detectDnsHijacking(hostname, cachedIps);
      return {
        success: true,
        ips: cachedIps,
        responseTimeMs: 0,
        cached: true,
        hijacked: hijackCheck.hijacked,
        hijackReason: hijackCheck.reason,
      };
    }
  }

  try {
    // Try IPv4 first (most common)
    let ips;
    try {
      ips = await resolveDnsWithTimeout(hostname, timeout, 4);
    } catch (err) {
      // If IPv4 fails, try IPv6
      try {
        ips = await resolveDnsWithTimeout(hostname, timeout, 6);
      } catch (err6) {
        // Both failed
        throw err; // Throw original IPv4 error
      }
    }

    const responseTimeMs = Date.now() - startTime;

    // Check for DNS hijacking
    const hijackCheck = detectDnsHijacking(hostname, ips);

    // Cache successful result
    if (useCache && !hijackCheck.hijacked) {
      cacheDnsResult(hostname, ips);
    }

    return {
      success: true,
      ips,
      responseTimeMs,
      cached: false,
      hijacked: hijackCheck.hijacked,
      hijackReason: hijackCheck.reason,
    };
  } catch (error) {
    const responseTimeMs = Date.now() - startTime;

    return {
      success: false,
      ips: [],
      responseTimeMs,
      error: error.message || 'DNS resolution failed',
      cached: false,
      hijacked: false,
    };
  }
}

/**
 * Extract hostname from URL
 */
function extractHostname(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch {
    // If URL parsing fails, assume it's already a hostname
    return url;
  }
}

/**
 * Clear DNS cache (useful for testing or manual refresh)
 */
function clearDnsCache(hostname) {
  if (hostname) {
    dnsCache.delete(hostname);
  } else {
    dnsCache.clear();
  }
}

/**
 * Get DNS cache statistics
 */
function getDnsCacheStats() {
  const entries = Array.from(dnsCache.entries()).map(([hostname, entry]) => ({
    hostname,
    ips: entry.ips,
    age: Date.now() - entry.timestamp,
  }));

  return {
    size: dnsCache.size,
    entries,
  };
}

module.exports = {
  resolveDns,
  extractHostname,
  clearDnsCache,
  getDnsCacheStats,
};
