#!/bin/bash
set -e

echo "[firewall] Initializing Linux firewall router..."

# Check IPv4 forwarding (enabled via compose sysctls)
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]; then
  sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
fi

# Select initial mode based on environment variable (defaults to Mode A)
MODE="${LAB_MODE:-A}"
case "$MODE" in
  "B"|"b"|"3tier"|"three-tier")
    /bin/bash /opt/firewall/rules/mode-b.sh
    ;;
  "custom"|"CUSTOM")
    /bin/bash /opt/firewall/rules/mode-custom.sh
    ;;
  *)
    /bin/bash /opt/firewall/rules/mode-a.sh
    ;;
esac

echo "[firewall] Starting internal control daemon..."
exec python3 /opt/firewall/fw_daemon.py
