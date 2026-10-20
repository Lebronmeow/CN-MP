#!/bin/bash
# Mode B: Three-Tier Architecture (Segmented Web -> App -> DB)
# Strict perimeter isolation: Client reaches Web only. Web calls App only. App calls DB only.
# Direct Client -> DB, Client -> App, and Web -> DB are blocked.

set -e

echo "[firewall] Applying Mode B (Three-Tier) firewall rules..."

# -------------------------------------------------------------
# 1. INPUT Chain Policy (Protection of the Firewall Router itself)
# -------------------------------------------------------------
iptables -P INPUT DROP
iptables -F INPUT

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT

# Allow established & related return packets
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow ICMP echo-request, time-exceeded, and unreachable (required for traceroute & ping)
iptables -A INPUT -p icmp -j ACCEPT

# Allow control daemon ONLY from dedicated management subnet (172.28.0.0/24)
iptables -A INPUT -s 172.28.0.0/24 -p tcp --dport 9099 -j ACCEPT

# Rate-limited logging for denied input packets
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "[FW-INPUT-DROP] " --log-level 4
iptables -A INPUT -j DROP

# -------------------------------------------------------------
# 2. FORWARD Chain Policy (Inter-Tier Transit Filtering)
# -------------------------------------------------------------
iptables -F FORWARD
iptables -Z FORWARD
iptables -P FORWARD DROP

# Stateful inspection
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow ICMP across tiers
iptables -A FORWARD -p icmp -j ACCEPT

# Tier 1: Client -> Web Server (HTTPS :443)
iptables -A FORWARD -s 192.168.1.20 -d 10.0.1.10 -p tcp --dport 443 -j ACCEPT

# Tier 2: Web Server -> FastAPI App Server (:5000)
iptables -A FORWARD -s 10.0.1.10 -d 10.0.2.10 -p tcp --dport 5000 -j ACCEPT

# Tier 3: FastAPI App Server -> Database Server (:3306)
iptables -A FORWARD -s 10.0.2.10 -d 10.0.3.10 -p tcp --dport 3306 -j ACCEPT

# Explicit logging and drop for direct database bypass from client
iptables -A FORWARD -s 192.168.1.20 -d 10.0.3.10 -p tcp --dport 3306 -j LOG --log-prefix "[FW-BLOCKED-CLIENT-DB] " --log-level 4
iptables -A FORWARD -s 192.168.1.20 -d 10.0.3.10 -p tcp --dport 3306 -j DROP

# Explicit drop for direct app tier bypass from client
iptables -A FORWARD -s 192.168.1.20 -d 10.0.2.10 -p tcp --dport 5000 -j DROP

# Rate-limited logging for other denied transit packets
iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "[FW-DROP-B] " --log-level 4
iptables -A FORWARD -j DROP

echo "[firewall] Mode B rules active. Strict three-tier pipeline enforced. INPUT default DROP active."
