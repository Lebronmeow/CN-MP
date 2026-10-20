#!/bin/bash
# Mode B: Three-Tier Architecture (Segmented Web -> App -> DB)
# Strict perimeter isolation: Client reaches Web only. Web calls App only. App calls DB only.
# Direct Client -> DB, Client -> App, and Web -> DB are blocked.

set -e

echo "[firewall] Applying Mode B (Three-Tier) firewall rules..."

# Flush existing FORWARD rules and zero counters
iptables -F FORWARD
iptables -Z FORWARD

# Set default policy for FORWARD chain to DROP
iptables -P FORWARD DROP

# 1. Stateful inspection: Allow ESTABLISHED and RELATED return traffic
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 2. Allow ICMP echo request/reply across tiers for network diagnostics and latency probing
iptables -A FORWARD -p icmp -j ACCEPT

# 3. Tier 1 entry: Allow Client (192.168.1.20) to reach Nginx Web Server (10.0.1.10) on HTTPS :443
iptables -A FORWARD -s 192.168.1.20 -d 10.0.1.10 -p tcp --dport 443 -j ACCEPT

# 4. Tier 2 internal hop: Allow Web Server (10.0.1.10) to reach FastAPI App Server (10.0.2.10) on port 5000
iptables -A FORWARD -s 10.0.1.10 -d 10.0.2.10 -p tcp --dport 5000 -j ACCEPT

# 5. Tier 3 internal hop: Allow FastAPI App Server (10.0.2.10) to query Database Server (10.0.3.10) on MySQL :3306
iptables -A FORWARD -s 10.0.2.10 -d 10.0.3.10 -p tcp --dport 3306 -j ACCEPT

# 6. Explicitly drop any direct bypass attempt from Client to DB (:3306) with custom log prefix
iptables -A FORWARD -s 192.168.1.20 -d 10.0.3.10 -p tcp --dport 3306 -j LOG --log-prefix "[FW-BLOCKED-CLIENT-DB] " --log-level 4
iptables -A FORWARD -s 192.168.1.20 -d 10.0.3.10 -p tcp --dport 3306 -j DROP

# 7. Explicitly drop any direct bypass attempt from Client to App (:5000)
iptables -A FORWARD -s 192.168.1.20 -d 10.0.2.10 -p tcp --dport 5000 -j DROP

# 8. Rate-limited logging for other denied packets
iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "[FW-DROP-B] " --log-level 4

# 9. Default drop for all remaining forwarded traffic
iptables -A FORWARD -j DROP

echo "[firewall] Mode B rules active. Strict three-tier pipeline enforced."
