#!/bin/bash
set -e

mkdir -p /etc/nginx/certs

if [ ! -f /etc/nginx/certs/server.crt ]; then
  echo "[web] Generating self-signed TLS certificates for port 443..."
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/certs/server.key \
    -out /etc/nginx/certs/server.crt \
    -subj "/CN=shopledger.local/O=ShopLedger/C=US" 2>/dev/null
fi

echo "[web] Configuring default route via firewall (10.0.1.254)..."
ip route del default 2>/dev/null || true
ip route add default via 10.0.1.254

echo "[web] Starting Nginx TLS Reverse Proxy & Static Web Server..."
exec nginx -g "daemon off;"
