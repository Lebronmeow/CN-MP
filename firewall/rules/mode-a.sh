#!/bin/bash
# Mode A: Two-Tier Architecture (Client-Server Direct Access)
# Client directly connects to the MySQL Database Server on port 3306.
# Web and Application tiers are bypassed.

set -e

echo "[firewall] Applying Mode A (Two-Tier) firewall rules..."

# Flush existing FORWARD rules and zero counters
iptables -F FORWARD
iptables -Z FORWARD

# Set default policy for FORWARD chain to DROP
# All inter-tier transit traffic is denied unless explicitly permitted below
iptables -P FORWARD DROP

# 1. Stateful inspection: Allow ESTABLISHED and RELATED return traffic
# Ensures response packets for legitimate outbound connections are permitted back
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 2. Allow ICMP echo request/reply across tiers for network diagnostics and latency probing
iptables -A FORWARD -p icmp -j ACCEPT

# 3. Mode A Core: Allow Client (192.168.1.20) direct TCP access to Database (10.0.3.10) on port 3306
# Models legacy/LAN two-tier applications (e.g. desktop billing, POS, internal ERP)
iptables -A FORWARD -s 192.168.1.20 -d 10.0.3.10 -p tcp --dport 3306 -j ACCEPT

# 4. Rate-limited logging for denied packets (maximum 5 entries/min to prevent syslog exhaustion)
iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "[FW-DROP-A] " --log-level 4

# 5. Default drop for all remaining forwarded traffic
iptables -A FORWARD -j DROP

echo "[firewall] Mode A rules active. State: Client -> DB (:3306) ALLOWED."
