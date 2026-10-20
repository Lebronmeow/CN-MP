#!/bin/bash
set -e

echo "[web] Adding default route via firewall (10.0.1.254)..."
ip route del default 2>/dev/null || true
ip route add default via 10.0.1.254

exec python3 /app/mock.py 443 "web-tier"
