#!/bin/bash
# Mode Custom: User-Defined Ruleset
# Initialized as a baseline stateful forward drop policy until custom rules are applied.

set -e

echo "[firewall] Applying Mode Custom base firewall rules..."

iptables -F FORWARD
iptables -Z FORWARD
iptables -P FORWARD DROP

# Stateful connection tracking
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ICMP ping
iptables -A FORWARD -p icmp -j ACCEPT

# Custom user rules are dynamically inserted above the drop rule
# Rate-limited logging for denied packets
iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "[FW-DROP-CUSTOM] " --log-level 4
iptables -A FORWARD -j DROP

echo "[firewall] Mode Custom baseline ready."
