#!/bin/bash
# Mode Custom: User-Defined Ruleset
# Baseline stateful forward drop policy until custom rules are applied.

set -e

echo "[firewall] Applying Mode Custom base firewall rules..."

# INPUT Chain Policy
iptables -P INPUT DROP
iptables -F INPUT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -s 172.28.0.0/24 -p tcp --dport 9099 -j ACCEPT
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "[FW-INPUT-DROP] " --log-level 4
iptables -A INPUT -j DROP

# FORWARD Chain Policy
iptables -F FORWARD
iptables -Z FORWARD
iptables -P FORWARD DROP
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -p icmp -j ACCEPT

iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "[FW-DROP-CUSTOM] " --log-level 4
iptables -A FORWARD -j DROP

echo "[firewall] Mode Custom baseline ready. INPUT default DROP active."
