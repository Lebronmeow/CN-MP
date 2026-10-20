#!/bin/bash
# Mode A: Two-Tier Architecture (Client-Server Direct Access)
# Client directly connects to the MySQL Database Server on port 3306.
# Web and Application tiers are bypassed.

set -e

echo "[firewall] Applying Mode A (Two-Tier) firewall rules..."

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

# Allow control daemon ONLY from dedicated management interface on mgmt subnet (172.28.0.0/24)
MGMT_IF=$(ip -4 route list match 172.28.0.0/24 2>/dev/null | awk '{print $3}' | head -n1)
if [ -n "$MGMT_IF" ]; then
  iptables -A INPUT -i "$MGMT_IF" -s 172.28.0.0/24 -p tcp --dport 9099 -j ACCEPT
fi

# Rate-limited logging for denied input packets
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "[FW-INPUT-DROP] " --log-level 4
iptables -A INPUT -j DROP

# -------------------------------------------------------------
# 2. FORWARD Chain Policy (Inter-Tier Transit Filtering)
# -------------------------------------------------------------
iptables -F FORWARD
iptables -Z FORWARD
iptables -P FORWARD DROP

# Stateful inspection: Allow ESTABLISHED and RELATED return traffic
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Mode A Core: Allow Client (192.168.1.20) direct TCP access to Database (10.0.3.10) on port 3306
iptables -A FORWARD -s 192.168.1.20 -d 10.0.3.10 -p tcp --dport 3306 -j ACCEPT

# Mode A Core: Allow Client direct ICMP access to Database for diagnostics (ping/traceroute)
iptables -A FORWARD -s 192.168.1.20 -d 10.0.3.10 -p icmp -j ACCEPT

# Rate-limited logging for denied forward packets
iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "[FW-DROP-A] " --log-level 4
iptables -A FORWARD -j DROP

echo "[firewall] Mode A rules active. State: Client -> DB (:3306) ALLOWED. INPUT default DROP active."
