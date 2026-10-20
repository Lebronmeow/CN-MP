#!/bin/bash
set -e

# Configure static route towards the internal server tiers via firewall
echo "[client] Configuring default route via firewall (192.168.1.254)..."
ip route del default 2>/dev/null || true
ip route add default via 192.168.1.254

exec "$@"
