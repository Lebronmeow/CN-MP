# Firewall Rules, Stateful Inspection & Router Configuration

## 1. Firewall Architecture

The firewall service (`lab_firewall`) runs Alpine Linux with `NET_ADMIN` capabilities and kernel IP forwarding enabled (`net.ipv4.ip_forward=1`). It is attached to all five network subnets:
- `client_net`: `192.168.1.254` (Interface `eth1`)
- `web_net`: `10.0.1.254` (Interface `eth2`)
- `app_net`: `10.0.2.254` (Interface `eth3`)
- `db_net`: `10.0.3.254` (Interface `eth4`)
- `mgmt_net`: `172.28.0.254` (Interface `eth0`)

---

## 2. Default-Drop Policy & Stateful Connection Tracking

Both Mode A and Mode B apply a strict default-drop policy on transit traffic:
```bash
iptables -P FORWARD DROP
```
Every packet must match an explicit rule or be logged and dropped.

### Stateful Inspection (`conntrack`)
To permit return packets without opening broad reverse firewall holes, both modes begin with stateful connection tracking:
```bash
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```
Return packets belonging to established TCP handshakes or ICMP echo replies are permitted automatically.

---

## 3. Mode Rulesets

### Mode A: Two-Tier Architecture ([`firewall/rules/mode-a.sh`](file:///f:/CN-MP/firewall/rules/mode-a.sh))
Permits direct client connection to MySQL and ICMP diagnostics:
```bash
# Allow client to reach database server on MySQL port 3306
iptables -A FORWARD -s 192.168.1.20 -d 10.0.3.10 -p tcp --dport 3306 -j ACCEPT

# Allow client to ping database server for latency diagnostics
iptables -A FORWARD -s 192.168.1.20 -d 10.0.3.10 -p icmp -j ACCEPT

# Rate-limited logging of denied packets
iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "[FW-DROP-A] "
iptables -A FORWARD -j DROP
```

---

### Mode B: Three-Tier Architecture ([`firewall/rules/mode-b.sh`](file:///f:/CN-MP/firewall/rules/mode-b.sh))
Enforces strict perimeter segmentation:
```bash
# Tier 1 -> Tier 2: Client to Web reverse proxy (HTTPS port 443)
iptables -A FORWARD -s 192.168.1.20 -d 10.0.1.10 -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -s 192.168.1.20 -d 10.0.1.10 -p icmp -j ACCEPT

# Tier 2 -> Tier 3: Web proxy to FastAPI application server (port 5000)
iptables -A FORWARD -s 10.0.1.10 -d 10.0.2.10 -p tcp --dport 5000 -j ACCEPT

# Tier 3 -> Tier 4: Application server to MySQL database (port 3306)
iptables -A FORWARD -s 10.0.2.10 -d 10.0.3.10 -p tcp --dport 3306 -j ACCEPT

# Explicit block on direct client-to-database bypass
iptables -A FORWARD -s 192.168.1.0/24 -d 10.0.3.0/24 -j DROP

# Rate-limited logging of denied packets
iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "[FW-DROP-B] "
iptables -A FORWARD -j DROP
```

---

## 4. Firewall Ingress Protection (`INPUT` Chain)

To prevent tenant containers from tampering with the firewall's internal control daemon (`fw_daemon.py` on port `9099`):
```bash
iptables -P INPUT DROP
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --dport 9099 -j ACCEPT
```
Port `9099` is strictly reachable **only** via `eth0` (`mgmt_net`). Port scans against `:9099` from `lab_client`, `lab_web`, `lab_app`, or `lab_db` show `filtered`.
