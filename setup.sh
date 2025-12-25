#!/bin/bash

# StatusBeacon Probe Setup Script
# Run: curl -s https://your-domain/probe-setup.sh | bash -s -- <region> <secret>
# Or:  wget -qO- https://your-domain/probe-setup.sh | bash -s -- <region> <secret>

set -e

REGION=${1:-"unknown"}
SECRET=${2:-""}
PORT=${3:-3002}
INSTALL_DIR="/opt/statusbeacon-probe"

echo "╔═══════════════════════════════════════════════════════╗"
echo "║       StatusBeacon Probe Setup                        ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# Check for Node.js
if ! command -v node &> /dev/null; then
    echo "Node.js not found. Installing..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

echo "Node.js version: $(node -v)"

# Create install directory
echo "Creating install directory: $INSTALL_DIR"
sudo mkdir -p $INSTALL_DIR
cd $INSTALL_DIR

# Create package.json
echo "Creating package.json..."
sudo tee package.json > /dev/null << 'PACKAGEJSON'
{
  "name": "statusbeacon-probe",
  "version": "1.0.0",
  "main": "probe.js",
  "scripts": { "start": "node probe.js" },
  "dependencies": { "express": "^4.18.2" }
}
PACKAGEJSON

# Create probe.js
echo "Creating probe.js..."
sudo tee probe.js > /dev/null << 'PROBEJS'
const express = require('express');
const http = require('http');
const https = require('https');
const net = require('net');
const { URL } = require('url');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3002;
const PROBE_SECRET = process.env.PROBE_SECRET || '';
const PROBE_REGION = process.env.PROBE_REGION || 'unknown';

const GEO_BLOCKING_STATUS_CODES = [403, 451, 406];
const GEO_BLOCKING_PATTERNS = ['geo', 'region', 'country', 'blocked', 'restricted', 'not available', 'access denied', 'forbidden'];

function detectGeoBlocking(statusCode, errorMessage, responseBody) {
  if (GEO_BLOCKING_STATUS_CODES.includes(statusCode)) {
    const combined = `${errorMessage || ''} ${responseBody || ''}`.toLowerCase();
    for (const pattern of GEO_BLOCKING_PATTERNS) {
      if (combined.includes(pattern)) return { detected: true, reason: pattern };
    }
  }
  return { detected: false };
}

async function performHttpCheck(config) {
  const { url, method = 'GET', expectedStatus = 200, timeout = 30000, headers = {} } = config;
  const startTime = Date.now();
  
  return new Promise((resolve) => {
    try {
      const parsedUrl = new URL(url);
      const isHttps = parsedUrl.protocol === 'https:';
      const httpModule = isHttps ? https : http;
      
      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method, timeout,
        headers: { 'User-Agent': 'StatusBeacon-Probe/1.0', ...headers },
        rejectUnauthorized: !config.ignoreSslErrors
      };

      const req = httpModule.request(options, (res) => {
        let body = '';
        res.on('data', chunk => { body += chunk.toString().slice(0, 1000); });
        res.on('end', () => {
          const responseTime = Date.now() - startTime;
          const statusCode = res.statusCode;
          const isUp = statusCode === expectedStatus || (expectedStatus === 200 && statusCode >= 200 && statusCode < 300);
          resolve({ status: isUp ? 'up' : 'down', statusCode, responseTimeMs: responseTime, error: isUp ? null : `Expected ${expectedStatus}, got ${statusCode}`, geoBlocking: detectGeoBlocking(statusCode, '', body), region: PROBE_REGION });
        });
      });
      req.on('error', (error) => resolve({ status: 'down', statusCode: 0, responseTimeMs: Date.now() - startTime, error: error.message, geoBlocking: detectGeoBlocking(0, error.message, ''), region: PROBE_REGION }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 'down', statusCode: 0, responseTimeMs: timeout, error: 'Timeout', geoBlocking: { detected: false }, region: PROBE_REGION }); });
      req.end();
    } catch (error) {
      resolve({ status: 'down', statusCode: 0, responseTimeMs: Date.now() - startTime, error: error.message, geoBlocking: { detected: false }, region: PROBE_REGION });
    }
  });
}

async function performTcpCheck(config) {
  const { host, port, timeout = 10000 } = config;
  const startTime = Date.now();
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    socket.on('connect', () => { socket.destroy(); resolve({ status: 'up', responseTimeMs: Date.now() - startTime, error: null, region: PROBE_REGION }); });
    socket.on('error', (error) => { socket.destroy(); resolve({ status: 'down', responseTimeMs: Date.now() - startTime, error: error.message, region: PROBE_REGION }); });
    socket.on('timeout', () => { socket.destroy(); resolve({ status: 'down', responseTimeMs: timeout, error: 'Timeout', region: PROBE_REGION }); });
    try { socket.connect(port, host); } catch (error) { resolve({ status: 'down', responseTimeMs: Date.now() - startTime, error: error.message, region: PROBE_REGION }); }
  });
}

function authMiddleware(req, res, next) {
  if (!PROBE_SECRET) return next();
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader !== `Bearer ${PROBE_SECRET}`) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

app.get('/health', (req, res) => res.json({ status: 'healthy', region: PROBE_REGION, version: '1.0.0', uptime: process.uptime(), timestamp: new Date().toISOString() }));

app.post('/check', authMiddleware, async (req, res) => {
  try {
    const { url, method, expectedStatus, timeout, headers, ignoreSslErrors, monitorType, host, port } = req.body;
    let result = (monitorType === 'tcp' || (!url && host && port)) ? await performTcpCheck({ host, port, timeout }) : await performHttpCheck({ url, method, expectedStatus, timeout, headers, ignoreSslErrors });
    res.json(result);
  } catch (error) { res.status(500).json({ status: 'error', error: error.message, region: PROBE_REGION }); }
});

app.get('/', (req, res) => res.json({ name: 'StatusBeacon Probe', version: '1.0.0', region: PROBE_REGION }));

app.listen(PORT, '0.0.0.0', () => console.log(`StatusBeacon Probe running on port ${PORT} [${PROBE_REGION}]`));
PROBEJS

# Install dependencies
echo "Installing dependencies..."
sudo npm install --production

# Create systemd service
echo "Creating systemd service..."
sudo tee /etc/systemd/system/statusbeacon-probe.service > /dev/null << EOF
[Unit]
Description=StatusBeacon Probe
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment=PORT=$PORT
Environment=PROBE_SECRET=$SECRET
Environment=PROBE_REGION=$REGION
ExecStart=/usr/bin/node probe.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
echo "Enabling and starting service..."
sudo systemctl daemon-reload
sudo systemctl enable statusbeacon-probe
sudo systemctl restart statusbeacon-probe

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║       Setup Complete!                                 ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║  Region: $REGION"
echo "║  Port:   $PORT"
echo "║  Status: $(sudo systemctl is-active statusbeacon-probe)"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "Commands:"
echo "  sudo systemctl status statusbeacon-probe"
echo "  sudo systemctl restart statusbeacon-probe"
echo "  sudo journalctl -u statusbeacon-probe -f"
echo ""
echo "Test: curl http://localhost:$PORT/health"
