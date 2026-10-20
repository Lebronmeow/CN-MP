#!/bin/bash
set -e

echo "[db] Adding default route via firewall (10.0.3.254)..."
ip route del default 2>/dev/null || true
ip route add default via 10.0.3.254

exec python3 /app/mock.py 3306 "db-tier"
