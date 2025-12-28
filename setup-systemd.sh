#!/bin/bash

###############################################################################
# StatusBeacon Probe - Systemd Installation Script
#
# This script sets up the probe as a persistent systemd service that:
# - Auto-starts on boot
# - Restarts automatically if it crashes
# - Keeps running when SSH disconnects
# - Proper logging with journald
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/swaqar/statusbeacon-probe/main/setup-systemd.sh | sudo bash -s -- <region> <secret> [port]
#
# Example:
#   sudo bash setup-systemd.sh sgp1 your-secret-key 3002
###############################################################################

set -e

REGION=${1:-"unknown"}
SECRET=${2:-""}
PORT=${3:-3002}
INSTALL_DIR="/opt/statusbeacon-probe"
SERVICE_USER="statusbeacon"

echo "╔═══════════════════════════════════════════════════════╗"
echo "║       StatusBeacon Probe - Systemd Setup             ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# Validate inputs
if [ -z "$SECRET" ] || [ "$SECRET" == "your-secret-key" ]; then
    echo "❌ ERROR: PROBE_SECRET is required!"
    echo "Usage: $0 <region> <secret> [port]"
    echo "Example: $0 sgp1 mySecretKey123 3002"
    exit 1
fi

echo "Configuration:"
echo "  Region: $REGION"
echo "  Port:   $PORT"
echo "  Install Dir: $INSTALL_DIR"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# Install Node.js if not present
if ! command -v node &> /dev/null; then
    echo "📦 Installing Node.js 20.x..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
fi

echo "✅ Node.js version: $(node -v)"

# Create dedicated user for service (more secure than root)
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "👤 Creating service user: $SERVICE_USER"
    useradd --system --no-create-home --shell /bin/false $SERVICE_USER
fi

# Check if this is an update or fresh install
if [ -d "$INSTALL_DIR" ]; then
    echo "📦 Existing installation detected - updating code..."
    cd $INSTALL_DIR

    # If it's a git repo, pull latest changes
    if [ -d ".git" ]; then
        echo "🔄 Pulling latest code from GitHub..."
        git pull origin main
    else
        # Not a git repo, download all files
        echo "📥 Downloading latest code files..."
        curl -sSL https://raw.githubusercontent.com/swaqar/statusbeacon-probe/main/package.json -o package.json
        curl -sSL https://raw.githubusercontent.com/swaqar/statusbeacon-probe/main/probe.js -o probe.js
        curl -sSL https://raw.githubusercontent.com/swaqar/statusbeacon-probe/main/userAgents.js -o userAgents.js
        curl -sSL https://raw.githubusercontent.com/swaqar/statusbeacon-probe/main/geoBlockDetection.js -o geoBlockDetection.js
        curl -sSL https://raw.githubusercontent.com/swaqar/statusbeacon-probe/main/dnsMonitoring.js -o dnsMonitoring.js
        curl -sSL https://raw.githubusercontent.com/swaqar/statusbeacon-probe/main/cookieJar.js -o cookieJar.js
    fi
else
    # Fresh install - clone from git
    echo "📁 Fresh installation - cloning from GitHub..."

    # Install git if not present
    if ! command -v git &> /dev/null; then
        echo "📦 Installing git..."
        apt-get install -y git
    fi

    # Clone repository
    git clone https://github.com/swaqar/statusbeacon-probe.git $INSTALL_DIR
    cd $INSTALL_DIR
fi

# Ensure package.json exists (for non-git downloads)
if [ ! -f "package.json" ]; then
    echo "📝 Creating package.json..."
    cat > package.json << 'EOF'
{
  "name": "statusbeacon-probe",
  "version": "1.0.0",
  "main": "probe.js",
  "scripts": {
    "start": "node probe.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "tough-cookie": "^4.1.3"
  }
}
EOF
fi

# Function to create probe.js if download fails
create_probe_js() {
    cat > probe.js << 'PROBEJS'
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
const GEO_BLOCKING_PATTERNS = ['geo', 'region', 'country', 'location', 'blocked', 'restricted', 'not available', 'access denied', 'forbidden', 'cloudflare'];

function detectGeoBlocking(statusCode, errorMessage, responseBody) {
  if (GEO_BLOCKING_STATUS_CODES.includes(statusCode)) {
    const combined = `${errorMessage || ''} ${responseBody || ''}`.toLowerCase();
    for (const pattern of GEO_BLOCKING_PATTERNS) {
      if (combined.includes(pattern)) {
        return { detected: true, reason: `Possible geo-blocking: ${pattern} detected` };
      }
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
          const geoBlocking = detectGeoBlocking(statusCode, '', body);
          resolve({
            status: isUp ? 'up' : 'down',
            statusCode,
            responseTimeMs: responseTime,
            error: isUp ? null : `Expected ${expectedStatus}, got ${statusCode}`,
            geoBlocking,
            region: PROBE_REGION
          });
        });
      });

      req.on('error', (error) => {
        const responseTime = Date.now() - startTime;
        const geoBlocking = detectGeoBlocking(0, error.message, '');
        resolve({ status: 'down', statusCode: 0, responseTimeMs: responseTime, error: error.message, geoBlocking, region: PROBE_REGION });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({ status: 'down', statusCode: 0, responseTimeMs: timeout, error: 'Request timeout', geoBlocking: { detected: false }, region: PROBE_REGION });
      });

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
    socket.on('connect', () => {
      const responseTime = Date.now() - startTime;
      socket.destroy();
      resolve({ status: 'up', responseTimeMs: responseTime, error: null, region: PROBE_REGION });
    });
    socket.on('error', (error) => {
      socket.destroy();
      resolve({ status: 'down', responseTimeMs: Date.now() - startTime, error: error.message, region: PROBE_REGION });
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ status: 'down', responseTimeMs: timeout, error: 'Connection timeout', region: PROBE_REGION });
    });
    try {
      socket.connect(port, host);
    } catch (error) {
      resolve({ status: 'down', responseTimeMs: Date.now() - startTime, error: error.message, region: PROBE_REGION });
    }
  });
}

function authMiddleware(req, res, next) {
  if (!PROBE_SECRET) {
    console.warn('⚠️  PROBE_SECRET not set - authentication disabled!');
    return next();
  }
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader !== `Bearer ${PROBE_SECRET}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    region: PROBE_REGION,
    version: '1.0.0',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

app.post('/check', authMiddleware, async (req, res) => {
  try {
    const { url, method, expectedStatus, timeout, headers, ignoreSslErrors, monitorType, host, port } = req.body;
    let result;
    if (monitorType === 'tcp' || (!url && host && port)) {
      result = await performTcpCheck({ host, port, timeout });
    } else if (url) {
      result = await performHttpCheck({ url, method, expectedStatus, timeout, headers, ignoreSslErrors });
    } else {
      return res.status(400).json({ error: 'Missing url or host/port' });
    }
    res.json(result);
  } catch (error) {
    console.error('Check error:', error);
    res.status(500).json({ status: 'error', error: error.message, region: PROBE_REGION });
  }
});

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

app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔═══════════════════════════════════════════════════════╗
║           StatusBeacon Probe v1.0.0                   ║
╠═══════════════════════════════════════════════════════╣
║  Port:   ${PORT.toString().padEnd(44)}║
║  Region: ${PROBE_REGION.padEnd(44)}║
║  Auth:   ${(PROBE_SECRET ? 'Enabled ✓' : 'DISABLED ⚠️').padEnd(44)}║
╚═══════════════════════════════════════════════════════╝
  `);
});
PROBEJS
}

# Install dependencies
echo "📦 Installing dependencies..."
npm install --production

# Set ownership
chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR

# Create environment file (easier to update configuration)
echo "⚙️  Creating environment file..."
cat > /etc/statusbeacon-probe.env << EOF
PORT=$PORT
PROBE_SECRET=$SECRET
PROBE_REGION=$REGION
NODE_ENV=production
NODE_NO_HTTP2=1
EOF

chmod 600 /etc/statusbeacon-probe.env

# Create systemd service
echo "🔧 Creating systemd service..."
cat > /etc/systemd/system/statusbeacon-probe.service << EOF
[Unit]
Description=StatusBeacon Probe Service
Documentation=https://github.com/swaqar/statusbeacon-probe
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=/etc/statusbeacon-probe.env
ExecStart=/usr/bin/node $INSTALL_DIR/probe.js

# Restart policy
Restart=always
RestartSec=10
StartLimitInterval=5min
StartLimitBurst=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=statusbeacon-probe

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
echo "🚀 Enabling and starting service..."
systemctl daemon-reload
systemctl enable statusbeacon-probe
systemctl restart statusbeacon-probe

# Wait a moment for service to start
sleep 2

# Check status
SERVICE_STATUS=$(systemctl is-active statusbeacon-probe)
SERVICE_ENABLED=$(systemctl is-enabled statusbeacon-probe)

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║       ✅ Setup Complete!                              ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║  Region:  $REGION"
echo "║  Port:    $PORT"
echo "║  Status:  $SERVICE_STATUS"
echo "║  Enabled: $SERVICE_ENABLED"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# Test health endpoint
echo "🔍 Testing health endpoint..."
sleep 1
if curl -s http://localhost:$PORT/health > /dev/null; then
    echo "✅ Probe is responding on port $PORT"
    curl -s http://localhost:$PORT/health | head -5
else
    echo "⚠️  Probe not responding yet, check logs"
fi

echo ""
echo "📋 Useful Commands:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  View status:       sudo systemctl status statusbeacon-probe"
echo "  View logs:         sudo journalctl -u statusbeacon-probe -f"
echo "  Restart service:   sudo systemctl restart statusbeacon-probe"
echo "  Stop service:      sudo systemctl stop statusbeacon-probe"
echo "  Disable service:   sudo systemctl disable statusbeacon-probe"
echo ""
echo "  Update config:     sudo nano /etc/statusbeacon-probe.env"
echo "                     sudo systemctl restart statusbeacon-probe"
echo ""
echo "  Test health:       curl http://localhost:$PORT/health"
echo "  Test externally:   curl http://$(curl -s ifconfig.me):$PORT/health"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔐 IMPORTANT: Make sure to allow port $PORT in your firewall!"
echo "   For UFW: sudo ufw allow $PORT"
echo ""
echo "📝 Add this to your main server's PROBE_ENDPOINTS:"
echo "   $REGION=http://$(curl -s ifconfig.me):$PORT"
echo ""
