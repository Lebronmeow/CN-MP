#!/bin/bash
set -e

mkdir -p /captures

echo "[sniffer] Detecting firewall router interfaces..."
IF_CLIENT=$(ip -4 addr show | grep '192.168.1.254' | awk '{print $NF}')
IF_WEB=$(ip -4 addr show | grep '10.0.1.254' | awk '{print $NF}')
IF_APP=$(ip -4 addr show | grep '10.0.2.254' | awk '{print $NF}')
IF_DB=$(ip -4 addr show | grep '10.0.3.254' | awk '{print $NF}')

echo "[sniffer] Detected: client_net=$IF_CLIENT, web_net=$IF_WEB, app_net=$IF_APP, db_net=$IF_DB"

# Per-interface captures: produces clean Ethernet frames (EN10MB) per tier
[ -n "$IF_CLIENT" ] && tcpdump -i "$IF_CLIENT" -n -U -W 3 -C 5 -w /captures/client.pcap &
[ -n "$IF_WEB" ] && tcpdump -i "$IF_WEB" -n -U -W 3 -C 5 -w /captures/web.pcap &
[ -n "$IF_APP" ] && tcpdump -i "$IF_APP" -n -U -W 3 -C 5 -w /captures/app.pcap &
[ -n "$IF_DB" ] && tcpdump -i "$IF_DB" -n -U -W 3 -C 5 -w /captures/db.pcap &

# Combined live capture across all interfaces
echo "[sniffer] Starting rotating live capture on any..."
exec tcpdump -i any -n -U -W 5 -C 10 -w /captures/live.pcap
