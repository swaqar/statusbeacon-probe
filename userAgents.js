/**
 * User-Agent Rotation Library (JavaScript version for probe)
 */

// Realistic Chrome User-Agents
const CHROME_USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
];

const FIREFOX_USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0',
  'Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0',
];

const ALL_USER_AGENTS = [...CHROME_USER_AGENTS, ...FIREFOX_USER_AGENTS];
const ACCEPT_LANGUAGES = ['en-US,en;q=0.9', 'en-GB,en;q=0.9', 'en,en-US;q=0.9'];

let rotationIndex = 0;

function getUserAgent(strategy = 'rotate') {
  switch (strategy) {
    case 'rotate':
      const ua = ALL_USER_AGENTS[rotationIndex % ALL_USER_AGENTS.length];
      rotationIndex++;
      return ua;
    case 'random':
      return ALL_USER_AGENTS[Math.floor(Math.random() * ALL_USER_AGENTS.length)];
    default:
      return CHROME_USER_AGENTS[0];
  }
}

function parseBrowserInfo(userAgent) {
  let browser = 'Chrome';
  let version = '131';
  let os = 'Windows';

  if (userAgent.includes('Firefox')) {
    browser = 'Firefox';
    const match = userAgent.match(/Firefox\/(\d+)/);
    version = match ? match[1] : '123';
  } else if (userAgent.includes('Chrome')) {
    browser = 'Chrome';
    const match = userAgent.match(/Chrome\/(\d+)/);
    version = match ? match[1] : '131';
  }

  if (userAgent.includes('Windows')) os = 'Windows';
  else if (userAgent.includes('Macintosh')) os = 'macOS';
  else if (userAgent.includes('Linux')) os = 'Linux';

  return { browser, version, os };
}

function getBrowserHeaders(userAgent) {
  const { browser, version, os } = parseBrowserInfo(userAgent);
  const acceptLanguage = ACCEPT_LANGUAGES[Math.floor(Math.random() * ACCEPT_LANGUAGES.length)];

  const headers = {
    'User-Agent': userAgent,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': acceptLanguage,
    'Accept-Encoding': 'gzip, deflate, br',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
  };

  if (browser === 'Chrome') {
    headers['Sec-Ch-Ua'] = `"Google Chrome";v="${version}", "Chromium";v="${version}", "Not_A Brand";v="24"`;
    headers['Sec-Ch-Ua-Mobile'] = '?0';
    headers['Sec-Ch-Ua-Platform'] = os === 'Windows' ? '"Windows"' : os === 'macOS' ? '"macOS"' : '"Linux"';
    headers['Sec-Fetch-Dest'] = 'document';
    headers['Sec-Fetch-Mode'] = 'navigate';
    headers['Sec-Fetch-Site'] = 'none';
    headers['Sec-Fetch-User'] = '?1';
    headers['Upgrade-Insecure-Requests'] = '1';
  }

  return headers;
}

function getHeadersObject(strategy = 'rotate') {
  const userAgent = getUserAgent(strategy);
  return getBrowserHeaders(userAgent);
}

module.exports = {
  getUserAgent,
  getBrowserHeaders,
  getHeadersObject,
};
