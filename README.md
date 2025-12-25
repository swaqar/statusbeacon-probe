# StatusBeacon Probe

<div align="center">

**Lightweight, standalone probe service for multi-region uptime monitoring**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D%2020.0.0-brightgreen)](https://nodejs.org)

[Quick Start](#-quick-start) •
[Features](#-features) •
[Installation](#-installation) •
[Configuration](#-configuration) •
[Commands](#-commands)

</div>

---

## 🚀 Quick Start

**One command installation with systemd (auto-start on boot, auto-restart on failure)**

SSH into your DigitalOcean droplet and run:

```bash
curl -sSL https://raw.githubusercontent.com/swaqar/statusbeacon-probe/main/setup-systemd.sh | sudo bash -s -- <region> <secret> <port>
```

**Example:**
```bash
curl -sSL https://raw.githubusercontent.com/swaqar/statusbeacon-probe/main/setup-systemd.sh | sudo bash -s -- fra1 mySecretKey123 3002
```

That's it! Your probe is now running as a persistent systemd service. ✅

---

## ✨ Features

- 🌍 **Multi-region monitoring** - Deploy probes globally for accurate regional health checks
- 🔄 **Auto-restart** - Systemd service automatically restarts on failure
- 🚀 **Auto-start** - Starts automatically on server boot
- 🔒 **Secure** - Runs as dedicated non-root user with security hardening
- 📊 **HTTP & TCP checks** - Monitor websites, APIs, and TCP services
- 🚨 **Geo-blocking detection** - Automatically detects regional access restrictions
- 📝 **Structured logging** - Centralized logs with journald
- ⚡ **Lightweight** - Minimal resource usage (~20MB RAM)

---

## 📦 Installation

### Method 1: Automated Systemd Setup (Recommended)

This method creates a production-ready service:
- Auto-starts on boot
- Auto-restarts on failure
- Survives SSH disconnects
- Proper logging

```bash
curl -sSL https://raw.githubusercontent.com/swaqar/statusbeacon-probe/main/setup-systemd.sh | sudo bash -s -- <region> <secret> <port>
```

**Parameters:**
- `<region>` - DigitalOcean region code (nyc1, fra1, sgp1, etc.)
- `<secret>` - Shared secret for API authentication
- `<port>` - Port to listen on (default: 3002)

### Method 2: Manual Installation

```bash
# Install Node.js 20.x
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Clone repository
git clone https://github.com/swaqar/statusbeacon-probe.git
cd statusbeacon-probe

# Install dependencies
npm install --production

# Run probe
PROBE_REGION=fra1 PROBE_SECRET=your-secret PORT=3002 node probe.js
```

### Method 3: Docker

```bash
docker run -d \
  --name statusbeacon-probe \
  -p 3002:3002 \
  -e PROBE_REGION=fra1 \
  -e PROBE_SECRET=your-secret \
  -e PORT=3002 \
  --restart unless-stopped \
  statusbeacon/probe:latest
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PROBE_REGION` | No | `unknown` | Region identifier (e.g., `fra1`, `nyc3`, `sgp1`) |
| `PROBE_SECRET` | **Yes** | - | Shared secret for authentication |
| `PORT` | No | `3002` | Port to listen on |
| `NODE_ENV` | No | `development` | Environment mode |

### Systemd Configuration

Configuration is stored in `/etc/statusbeacon-probe.env`:

```bash
# Edit configuration
sudo nano /etc/statusbeacon-probe.env

# Restart to apply changes
sudo systemctl restart statusbeacon-probe
```

Or use the update script:

```bash
curl -sSL https://raw.githubusercontent.com/swaqar/statusbeacon-probe/main/update-config.sh | sudo bash
```

---

## 📋 Commands

### Systemd Service Management

```bash
# View status
sudo systemctl status statusbeacon-probe

# View live logs
sudo journalctl -u statusbeacon-probe -f

# Restart service
sudo systemctl restart statusbeacon-probe

# Stop service
sudo systemctl stop statusbeacon-probe

# Start service
sudo systemctl start statusbeacon-probe

# Disable auto-start
sudo systemctl disable statusbeacon-probe

# Enable auto-start
sudo systemctl enable statusbeacon-probe
```

### Testing

```bash
# Health check (local)
curl http://localhost:3002/health

# Health check (external)
curl http://YOUR_PROBE_IP:3002/health

# Perform HTTP check (requires auth)
curl -X POST http://localhost:3002/check \
  -H "Authorization: Bearer your-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "method": "GET",
    "expectedStatus": 200,
    "timeout": 10000
  }'
```

---

## 🔌 API Endpoints

### `GET /health`

Health check endpoint (no authentication required)

**Response:**
```json
{
  "status": "healthy",
  "region": "fra1",
  "version": "1.0.0",
  "uptime": 123.45,
  "timestamp": "2024-12-26T00:00:00.000Z"
}
```

### `POST /check`

Perform monitoring check (requires authentication)

**Headers:**
```
Authorization: Bearer your-secret
Content-Type: application/json
```

**Request Body (HTTP Check):**
```json
{
  "url": "https://example.com",
  "method": "GET",
  "expectedStatus": 200,
  "timeout": 30000,
  "headers": {},
  "ignoreSslErrors": false
}
```

**Request Body (TCP Check):**
```json
{
  "host": "example.com",
  "port": 443,
  "timeout": 10000,
  "monitorType": "tcp"
}
```

**Response:**
```json
{
  "status": "up",
  "statusCode": 200,
  "responseTimeMs": 145,
  "error": null,
  "geoBlocking": {
    "detected": false
  },
  "region": "fra1"
}
```

---

## 🌍 Supported Regions

Use DigitalOcean region codes:

| Region Code | Location |
|-------------|----------|
| `nyc1`, `nyc2`, `nyc3` | New York, USA |
| `sfo2`, `sfo3` | San Francisco, USA |
| `tor1` | Toronto, Canada |
| `ams2`, `ams3` | Amsterdam, Netherlands |
| `lon1` | London, UK |
| `fra1` | Frankfurt, Germany |
| `sgp1` | Singapore |
| `blr1` | Bangalore, India |
| `syd1` | Sydney, Australia |

---

## 🔐 Security

### Firewall Configuration

Allow probe port in your firewall:

```bash
# UFW
sudo ufw allow 3002

# iptables
sudo iptables -A INPUT -p tcp --dport 3002 -j ACCEPT
```

### Security Hardening (Systemd)

The systemd service includes security hardening:
- Runs as dedicated `statusbeacon` user (not root)
- `NoNewPrivileges=true` - Prevents privilege escalation
- `PrivateTmp=true` - Isolated /tmp directory
- `ProtectSystem=strict` - Read-only system directories
- `ProtectHome=true` - Inaccessible home directories

---

## 🔄 Updates

### Update probe code

```bash
cd /opt/statusbeacon-probe
sudo git pull
sudo npm install --production
sudo systemctl restart statusbeacon-probe
```

### Update configuration only

```bash
sudo nano /etc/statusbeacon-probe.env
sudo systemctl restart statusbeacon-probe
```

---

## 🛠️ Troubleshooting

### Service won't start

```bash
# Check logs
sudo journalctl -u statusbeacon-probe -n 50 --no-pager

# Check if port is in use
sudo lsof -i :3002

# Verify file permissions
ls -la /opt/statusbeacon-probe/
```

### Can't connect from main server

```bash
# Verify service is running
sudo systemctl status statusbeacon-probe

# Check if port is open
sudo netstat -tlnp | grep 3002

# Test locally first
curl http://localhost:3002/health

# Check firewall
sudo ufw status
```

### View detailed logs

```bash
# Last 100 lines
sudo journalctl -u statusbeacon-probe -n 100

# Last hour
sudo journalctl -u statusbeacon-probe --since "1 hour ago"

# Follow live logs
sudo journalctl -u statusbeacon-probe -f
```

---

## 📚 Documentation

- [Quick Start Guide](QUICK-START.md) - Fast deployment guide
- [Main Application](https://github.com/swaqar/status-beacon-47) - StatusBeacon monitoring platform

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

---

## 💬 Support

- 🐛 [Report Issues](https://github.com/swaqar/statusbeacon-probe/issues)
- 📖 [Documentation](https://github.com/swaqar/statusbeacon-probe)

---

<div align="center">

**Built with ❤️ for reliable uptime monitoring**

</div>
