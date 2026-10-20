#!/bin/bash
set -e

# Identify client_net interface (assigned 192.168.1.20)
CLIENT_IF=$(ip -br -4 addr show 2>/dev/null | grep '192.168.1.20' | awk '{print $1}' | cut -d'@' -f1 | head -n1)
if [ -z "$CLIENT_IF" ]; then
  CLIENT_IF="eth0"
fi

echo "[client] Configuring default route via firewall (192.168.1.254) on interface $CLIENT_IF..."
ip route del default 2>/dev/null || true
ip route add default via 192.168.1.254 dev "$CLIENT_IF"

# Start host browser ingress relay on 8443 -> web:443
echo "[client] Starting host browser ingress relay on :8443 -> 10.0.1.10:443..."
socat TCP-LISTEN:8443,fork,reuseaddr TCP:10.0.1.10:443 &

exec "$@"
