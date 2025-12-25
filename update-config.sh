#!/bin/bash

###############################################################################
# StatusBeacon Probe - Configuration Update Script
#
# Easily update probe configuration without reinstalling
#
# Usage:
#   sudo bash update-config.sh [region] [secret] [port]
###############################################################################

set -e

ENV_FILE="/etc/statusbeacon-probe.env"

if [ ! -f "$ENV_FILE" ]; then
    echo "❌ Probe not installed. Run setup-systemd.sh first."
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

echo "╔═══════════════════════════════════════════════════════╗"
echo "║       StatusBeacon Probe - Update Configuration      ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# Show current configuration
echo "Current configuration:"
cat $ENV_FILE
echo ""

# Get new values or keep existing
read -p "New PROBE_REGION (or press Enter to keep current): " NEW_REGION
read -p "New PROBE_SECRET (or press Enter to keep current): " NEW_SECRET
read -p "New PORT (or press Enter to keep current): " NEW_PORT

# Load current values
source $ENV_FILE

# Update values if provided
REGION=${NEW_REGION:-$PROBE_REGION}
SECRET=${NEW_SECRET:-$PROBE_SECRET}
PORT=${NEW_PORT:-$PORT}

# Write updated configuration
echo "⚙️  Updating configuration..."
cat > $ENV_FILE << EOF
PORT=$PORT
PROBE_SECRET=$SECRET
PROBE_REGION=$REGION
NODE_ENV=production
EOF

chmod 600 $ENV_FILE

echo "✅ Configuration updated!"
echo ""
echo "New configuration:"
cat $ENV_FILE
echo ""

# Restart service
read -p "Restart probe service now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🔄 Restarting service..."
    systemctl restart statusbeacon-probe
    sleep 2
    systemctl status statusbeacon-probe --no-pager
    echo ""
    echo "✅ Service restarted successfully!"
else
    echo "⚠️  Remember to restart the service manually:"
    echo "   sudo systemctl restart statusbeacon-probe"
fi
