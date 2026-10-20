#!/bin/bash
set -e

# Configure static route towards the internal server tiers via firewall router
echo "[client] Configuring default route via firewall (192.168.1.254)..."
ip route del default 2>/dev/null || true
ip route add default via 192.168.1.254

# Start transparent host browser ingress relay on port 8443 -> web:443
# Traffic flow: Host (localhost:8443) -> client container (192.168.1.20) -> Firewall Router -> web (10.0.1.10:443)
echo "[client] Starting host browser ingress relay on :8443 -> 10.0.1.10:443..."
socat TCP-LISTEN:8443,fork,reuseaddr TCP:10.0.1.10:443 &

exec "$@"
