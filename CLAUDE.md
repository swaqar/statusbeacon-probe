# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

**StatusBeacon Probe** is a lightweight, standalone monitoring probe service deployed to multiple geographic regions (DigitalOcean droplets). Probes receive check requests from the main StatusBeacon server, perform HTTP/TCP health checks, and return detailed results including geo-blocking detection, rate limiting, SSL errors, DNS failures, and performance metrics.

## Deployment Model

This is a **public repository** deployed via direct GitHub access:
- Probes are installed/updated using: `curl -sSL https://raw.githubusercontent.com/swaqar/statusbeacon-probe/main/setup-systemd.sh | sudo bash -s -- <region> <secret> <port>`
- Code runs at `/opt/statusbeacon-probe` on probe servers
- Managed as a systemd service (`statusbeacon-probe.service`)
- Auto-updates via `git pull` when running setup script again

**CRITICAL**: All code changes must be committed and pushed to GitHub's `main` branch before they take effect on deployed probes. Running the setup script pulls the latest code from GitHub.

## Core Architecture

### Main Entry Point
- **`probe.js`** - Express.js server with two endpoints:
  - `GET /health` - Health check (no auth)
  - `POST /check` - Perform monitoring check (requires Bearer token auth)

### Detection Modules (Standalone Libraries)

The probe uses a modular architecture where each detection capability is a self-contained library:

1. **`geoBlockDetection.js`** - Detects geo-blocking, Cloudflare challenges, WAF blocks, and bot challenges
   - Returns `{ detected, type, reason, confidence }` where `type` can be: `'cloudflare'`, `'waf'`, `'rate_limit'`, `'geo_blocking'`, or `'challenge'`
   - **CRITICAL**: Fast-403 heuristic was removed due to false positives (commit 5a2c5da)

2. **`userAgents.js`** - User-Agent rotation to bypass basic bot detection
   - Provides realistic Chrome/Firefox User-Agents with proper browser headers (Sec-Ch-Ua, etc.)
   - Strategies: `'rotate'` (sequential), `'random'`, or `'default'`

3. **`rateLimitDetection.js`** - Parses rate limit headers (X-RateLimit-*, Retry-After, etc.)

4. **`redirectTracking.js`** - Manually follows redirects, tracks chains, detects geo-redirects

5. **`cookieJar.js`** - Per-monitor cookie storage for session-based monitoring

6. **`dnsMonitoring.js`** - DNS resolution with hijacking detection

7. **`timingBreakdown.js`** - Detailed timing metrics (DNS, TLS, TTFB, etc.)

### Check Flow

```
POST /check
  ↓
1. Auth verification (Bearer token)
  ↓
2. DNS resolution (dnsMonitoring.js)
  ↓
3. HTTP/TCP check execution
   ├─ User-Agent rotation (userAgents.js)
   ├─ Cookie handling (cookieJar.js)
   ├─ Redirect tracking (redirectTracking.js)
   └─ Response collection
  ↓
4. Detection pipeline
   ├─ Geo-blocking detection (geoBlockDetection.js)
   ├─ Rate limit detection (rateLimitDetection.js)
   └─ Timing breakdown (timingBreakdown.js)
  ↓
5. Build detectionMetadata object
  ↓
6. Return result with all metrics
```

### Detection Metadata Structure

The probe returns `detectionMetadata` as a JSON object when blocking is detected:

```javascript
{
  geoBlocking: {
    detected: true,
    type: 'cloudflare', // or 'waf', 'rate_limit', 'geo_blocking', 'challenge'
    reason: 'Cloudflare Ray ID detected',
    confidence: 'high',
    // ... additional fields
  },
  rateLimit: { /* if detected */ },
  geoRedirect: { /* if detected */ },
  detectedAt: '2024-01-01T00:00:00.000Z'
}
```

**IMPORTANT**: `detectionMetadata` is only set when detection occurs. If no blocking is detected, it's `null`.

## Critical Fixes & Known Issues

### ✅ Fixed: False Geo-Blocking Alerts (Commit 5a2c5da)

**Problem**: Fast-403 responses (<100ms) were incorrectly flagged as geo-blocking.

**Root Cause**: The heuristic `statusCode === 403 && responseTime < 100` incorrectly caught:
- Bot detection (Cloudflare, WAF)
- Auth failures
- CDN edge rejections

**Solution**:
1. Removed fast-403 heuristic from `geoBlockDetection.js` (line 291)
2. Changed `isGeoBlocked` logic in `probe.js` to only set true for `type === 'geo_blocking'` (not for `'cloudflare'`, `'waf'`, etc.)

**Lines affected**:
- `geoBlockDetection.js:291` - Comment: "REMOVED: Fast 403 heuristic"
- `probe.js:360-361` - `isGeoBlocked: geoBlockDetection.detected && geoBlockDetection.type === 'geo_blocking'`
- `probe.js:422-423` - Same logic in error handler

### User-Agent Bypass Behavior

**Expected**: Sites like Claude.ai and ChatGPT return 403 when probed.
**Actual**: They return 200 because realistic User-Agents bypass Cloudflare.

This is **working as designed**. The probe uses realistic browser headers to:
- Bypass basic bot detection
- Measure real user experience
- Detect geo-blocking that affects actual users (not just bots)

## Development Commands

### Local Testing
```bash
# Start probe locally
PROBE_REGION=local PROBE_SECRET=test-secret PORT=3002 node probe.js

# Test health endpoint
curl http://localhost:3002/health

# Test HTTP check
curl -X POST http://localhost:3002/check \
  -H "Authorization: Bearer test-secret" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "method": "GET", "expectedStatus": 200, "timeout": 10000}'

# Test TCP check
curl -X POST http://localhost:3002/check \
  -H "Authorization: Bearer test-secret" \
  -H "Content-Type: application/json" \
  -d '{"host": "example.com", "port": 443, "timeout": 10000, "monitorType": "tcp"}'
```

### Deployment Validation

After pushing to GitHub, verify code is deployed on probe servers:

```bash
# SSH into probe server, then:

# Check geoBlockDetection.js has the fix
sudo grep -n "REMOVED: Fast 403 heuristic" /opt/statusbeacon-probe/geoBlockDetection.js
# Expected: Line 291 with comment

# Check probe.js has the isGeoBlocked fix
sudo grep -n "Only set isGeoBlocked to true for actual geo-blocking" /opt/statusbeacon-probe/probe.js
# Expected: Lines 360 and 422 with comment

# Check git commit
cd /opt/statusbeacon-probe && git log --oneline -3
# Expected: Latest commit from GitHub

# View service logs
sudo journalctl -u statusbeacon-probe -f
```

### Update Deployed Probes

```bash
# Option 1: Pull latest code manually
cd /opt/statusbeacon-probe
sudo git pull origin main
sudo systemctl restart statusbeacon-probe

# Option 2: Re-run setup script (pulls latest + restarts)
curl -sSL https://raw.githubusercontent.com/swaqar/statusbeacon-probe/main/setup-systemd.sh | \
  sudo bash -s -- nyc3 YOUR_SECRET 3002
```

## Testing Framework

Test monitors are defined in SQL scripts under `/tests/` directory:

- **`01-seed-test-monitors.sql`** - Creates 25+ test monitors covering:
  - Easy URLs (Google, GitHub, HTTPBin)
  - Difficult URLs (geo-restricted content, Cloudflare challenges)
  - TCP monitors (port checks)
  - Multi-region monitors

- **`02-validate-results.sql`** - Comprehensive validation queries with pass/fail logic

- **`03-cleanup-test-monitors.sql`** - Removes all test monitors

**Test Execution**: Tests run via pgAdmin4 on the Digital Ocean PostgreSQL database. The main server's cron job triggers probe checks every 1-5 minutes.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PROBE_REGION` | No | `unknown` | Region code (e.g., `nyc3`, `fra1`, `sgp1`) |
| `PROBE_SECRET` | **Yes** | - | Bearer token for `/check` endpoint auth |
| `PORT` | No | `3002` | HTTP server port |
| `NODE_ENV` | No | `development` | Environment mode |
| `NODE_NO_HTTP2` | No | - | Set to `1` to disable HTTP/2 |

## Code Guidelines

### When Adding New Detection Logic

1. Create a new standalone module (e.g., `newDetection.js`)
2. Export a detection function that returns `{ detected: boolean, ...details }`
3. Import and call in `probe.js` detection pipeline
4. Add results to `detectionMetadata` object (only if detected)
5. Test locally before pushing to GitHub
6. Deploy to probe servers and validate with test monitors

### When Modifying Existing Detection

1. **Read the existing module first** - Understand current logic
2. **Check git history** - See why previous decisions were made (e.g., fast-403 removal)
3. **Test with real URLs** - Use Claude.ai, ChatGPT, BBC iPlayer to verify
4. **Update test validation** - Modify `02-validate-results.sql` if pass criteria change
5. **Document in git commit** - Explain why the change prevents false positives/negatives

### Security Considerations

- All `/check` requests MUST verify Bearer token
- Never log sensitive data (URLs may contain tokens)
- Use `ProtectSystem=strict` in systemd service (read-only filesystem)
- Run as non-root user (`statusbeacon`)
- Validate all user inputs (timeout ranges, URL formats)

## Common Pitfalls

1. **Forgetting to push to GitHub**: Changes only take effect after `git push` + probe update
2. **Testing with wrong URLs**: Claude.ai/ChatGPT now return 200 (not 403) due to User-Agent bypass
3. **Assuming detectionMetadata is always set**: It's `null` when no blocking detected
4. **Not checking both error handlers**: probe.js has detection logic in 2 places (success + error paths)
5. **Breaking systemd service**: Always test locally before deploying (service may fail to start)

## Monitoring Probe Health

```bash
# Check if service is running
sudo systemctl status statusbeacon-probe

# View last 50 log lines
sudo journalctl -u statusbeacon-probe -n 50 --no-pager

# Check probe is responding
curl http://localhost:3002/health

# View real-time logs
sudo journalctl -u statusbeacon-probe -f
```

If probe is unresponsive:
1. Check logs for errors
2. Verify port 3002 is not blocked by firewall
3. Check if Node.js process crashed (OOM, uncaught exception)
4. Restart service: `sudo systemctl restart statusbeacon-probe`

## Code Search

This project uses Pommel for semantic code search.

\`\`\`bash
# Find code related to a concept
pm search "rate limiting logic" --json --limit 5

# Find implementations of a pattern
pm search "retry with exponential backoff" --level method --json

# Search within a specific area
pm search "validation" --path "src/Api/" --json
\`\`\`

**Tip:** Low scores (< 0.5) suggest weak matches - use Explorer to confirm.
