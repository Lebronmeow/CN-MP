#!/bin/bash
set -e

echo "[app] Configuring default route via firewall (10.0.2.254)..."
ip route del default 2>/dev/null || true
ip route add default via 10.0.2.254

echo "[app] Starting ShopLedger FastAPI Application Service on :5000..."
exec uvicorn main:app --host 0.0.0.0 --port 5000
