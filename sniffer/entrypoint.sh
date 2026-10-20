#!/bin/bash
set -e

mkdir -p /captures

echo "[sniffer] Starting packet sniffer on all router interfaces..."
echo "[sniffer] Rotating captures saved to /captures/live.pcap"

# Rotate captures: max 5 files of 10MB each
exec tcpdump -i any -n -U -W 5 -C 10 -w /captures/live.pcap
