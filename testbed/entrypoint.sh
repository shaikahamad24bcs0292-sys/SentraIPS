#!/bin/bash
set -e

ROLE=${GATEWAY_ROLE:-gateway-a}
echo "========================================="
echo " Starting IPsecIQ Testbed Node: $ROLE"
echo "========================================="

# 1. Configure internal subnet address on loopback
if [ "$ROLE" = "gateway-a" ]; then
    echo "[Setup] Configuring Gateway A internal IP: 10.10.1.1/24 on lo"
    ip addr add 10.10.1.1/24 dev lo || true
    # Add route for Gateway B subnet via Gateway B physical IP
    ip route add 10.10.2.0/24 via 172.28.0.20 dev eth0 || true
elif [ "$ROLE" = "gateway-b" ]; then
    echo "[Setup] Configuring Gateway B internal IP: 10.10.2.1/24 on lo"
    ip addr add 10.10.2.1/24 dev lo || true
    # Add route for Gateway A subnet via Gateway A physical IP
    ip route add 10.10.1.0/24 via 172.28.0.10 dev eth0 || true
fi

# 2. Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# 3. Ensure captures directory exists
mkdir -p /captures

# 4. Initialize strongSwan default config if missing
if [ ! -f /etc/ipsec.conf ]; then
    cat << 'EOF' > /etc/ipsec.conf
config setup
    charondebug="ike 1, knl 1, cfg 1"
    uniqueids=yes
EOF
fi

if [ ! -f /etc/ipsec.secrets ]; then
    touch /etc/ipsec.secrets
    chmod 600 /etc/ipsec.secrets
fi

# 5. Start strongSwan
echo "[Setup] Starting strongSwan IPsec daemon..."
ipsec start
sleep 1

# Check strongSwan status
ipsec status || true

# 6. If Gateway B, launch responder service in background
if [ "$ROLE" = "gateway-b" ]; then
    echo "[Setup] Launching responder services (HTTP :8080, UDP :5004)..."
    python3 /app/testbed/responder_service.py &
fi

echo "[Setup] $ROLE initialization complete. Ready for orchestrator."

# Keep container alive
exec tail -f /dev/null
