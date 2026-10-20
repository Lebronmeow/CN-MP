#!/bin/bash
set -e

echo "[db] Configuring default route via firewall (10.0.3.254)..."
ip route del default 2>/dev/null || true
ip route add default via 10.0.3.254

if [ "$#" -eq 0 ] || [ "${1:0:1}" = '-' ]; then
    set -- mysqld "$@"
fi

# Execute official MySQL 8 entrypoint
exec /usr/local/bin/docker-entrypoint.sh "$@"
