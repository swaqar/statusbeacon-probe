# StatusBeacon Probe - Quick Start Guide

## 🚀 One-Command Installation

SSH into your DigitalOcean droplet and run:

```bash
curl -sSL https://raw.githubusercontent.com/swaqar/status-beacon-47/main/probe/setup-systemd.sh | sudo bash -s -- <region> <secret> 3002
```

### Example: Install probe in Singapore (sgp1)

```bash
curl -sSL https://raw.githubusercontent.com/swaqar/status-beacon-47/main/probe/setup-systemd.sh | sudo bash -s -- sgp1 mySecretKey123 3002
```

**Replace:**
- `sgp1` with your DigitalOcean region code (nyc1, lon1, fra1, etc.)
- `mySecretKey123` with your actual PROBE_SECRET
- `3002` with desired port (optional, defaults to 3002)

---

## ✅ What This Does

1. ✅ Installs Node.js 20 (if not already installed)
2. ✅ Creates dedicated service user (secure, non-root)
3. ✅ Downloads and installs probe code
4. ✅ Creates systemd service that:
   - Auto-starts on boot
   - Restarts automatically if it crashes
   - Keeps running when SSH disconnects
   - Logs to journald
5. ✅ Tests the installation

---

## 📋 Common Commands

### Check Status
```bash
sudo systemctl status statusbeacon-probe
```

### View Logs (Live)
```bash
sudo journalctl -u statusbeacon-probe -f
```

### Restart Service
```bash
sudo systemctl restart statusbeacon-probe
```

### Stop Service
```bash
sudo systemctl stop statusbeacon-probe
```

### Start Service
```bash
sudo systemctl start statusbeacon-probe
```

---

## ⚙️ Update Configuration

### Method 1: Edit Environment File
```bash
sudo nano /etc/statusbeacon-probe.env
# Make your changes, then:
sudo systemctl restart statusbeacon-probe
```

### Method 2: Use Update Script
```bash
curl -sSL https://raw.githubusercontent.com/swaqar/status-beacon-47/main/probe/update-config.sh | sudo bash
```

---

## 🧪 Test Your Probe

### Test Locally (from the probe server)
```bash
curl http://localhost:3002/health
```

**Expected response:**
```json
{
  "status": "healthy",
  "region": "sgp1",
  "version": "1.0.0",
  "uptime": 123.45,
  "timestamp": "2024-12-26T00:00:00.000Z"
}
```

### Test Externally (from your main API server)
```bash
curl http://YOUR_PROBE_IP:3002/health
```

---

## 🔐 Firewall Setup

**Important:** Allow the probe port in your firewall!

### For UFW (Ubuntu Firewall):
```bash
sudo ufw allow 3002
sudo ufw status
```

### For iptables:
```bash
sudo iptables -A INPUT -p tcp --dport 3002 -j ACCEPT
sudo iptables-save
```

### For DigitalOcean Cloud Firewall:
1. Go to DigitalOcean Control Panel → Networking → Firewalls
2. Add inbound rule: TCP port 3002 from your API server IP

---

## 🌍 Configure Main Server

After installing probes, add them to your main API server's environment:

```bash
# In your main API server's .env file:
PROBE_ENDPOINTS="nyc1=http://PROBE_IP_1:3002,sgp1=http://PROBE_IP_2:3002,fra1=http://PROBE_IP_3:3002"
PROBE_SECRET=mySecretKey123
```

**Replace:**
- `PROBE_IP_1`, `PROBE_IP_2`, etc. with actual probe server IPs
- Use the same `PROBE_SECRET` for all probes

---

## 🗺️ Available Regions

Use these DigitalOcean region codes:

| Code | Location |
|------|----------|
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

## ❌ Troubleshooting

### Service won't start
```bash
# Check detailed logs
sudo journalctl -u statusbeacon-probe -n 50 --no-pager

# Check if port is already in use
sudo lsof -i :3002

# Check file permissions
ls -la /opt/statusbeacon-probe/
```

### Can't connect from main server
```bash
# Test if port is open
sudo netstat -tlnp | grep 3002

# Check firewall
sudo ufw status

# Test from main server
curl -v http://PROBE_IP:3002/health
```

### View all logs
```bash
sudo journalctl -u statusbeacon-probe --since "1 hour ago"
```

---

## 🔄 Reinstall / Uninstall

### Reinstall (keeps configuration)
```bash
curl -sSL https://raw.githubusercontent.com/swaqar/status-beacon-47/main/probe/setup-systemd.sh | sudo bash -s -- sgp1 mySecret 3002
```

### Complete Uninstall
```bash
sudo systemctl stop statusbeacon-probe
sudo systemctl disable statusbeacon-probe
sudo rm /etc/systemd/system/statusbeacon-probe.service
sudo rm /etc/statusbeacon-probe.env
sudo rm -rf /opt/statusbeacon-probe
sudo userdel statusbeacon
sudo systemctl daemon-reload
```

---

## 💡 Tips

1. **Use the same PROBE_SECRET** for all your probes and main server
2. **Open firewall ports** before testing connectivity
3. **Use private networking** if your probes and API server are in the same datacenter
4. **Monitor probe health** from your main server regularly
5. **Check logs** if monitors aren't receiving data from a region

---

## 📚 More Information

- Full README: [probe/README.md](README.md)
- Main project: [GitHub Repository](https://github.com/swaqar/status-beacon-47)
