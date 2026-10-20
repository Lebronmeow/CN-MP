#!/bin/bash
set -e

echo "[app] Adding default route via firewall (10.0.2.254)..."
ip route del default 2>/dev/null || true
ip route add default via 10.0.2.254

exec python3 /app/mock.py 5000 "app-tier"
