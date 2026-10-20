# 5-Minute Examiner Demonstration Script

This script provides an exact 5-minute walkthrough to demonstrate Network Workbench v2 to examiners or instructors.

---

## ⏱️ Minute 1: Two-Tier Architecture (Mode A)
**Narrative:** *"In Mode A, we deploy a legitimate Two-Tier client-server architecture, typical of Tally LAN accounting, hospital clinical terminals, and supermarket POS stations. The client connects directly to MySQL on port 3306."*

```bash
# 1. Switch firewall to Mode A
python lab.py mode-a

# 2. Query products directly from MySQL 8.0 using client_user restricted credentials
python lab.py client-cli products

# 3. View the active daily sales aggregation report
python lab.py client-cli daily-sales
```
**What to point out:**
- Traffic travels directly from `192.168.1.20` to `10.0.3.10:3306` across the firewall router.
- Round-trip latency is ultra-fast (~0.21 ms median) using native MySQL binary protocol.

---

## ⏱️ Minute 2: Three-Tier Architecture (Mode B)
**Narrative:** *"In Mode B, we enforce a strict Three-Tier web perimeter (Client → Nginx :443 → FastAPI :5000 → MySQL :3306). Direct client access to the database or application tier is blocked at the firewall."*

```bash
# 1. Switch firewall to Mode B
python lab.py mode-b

# 2. Verify that direct client access to MySQL is now BLOCKED
python lab.py client-cli products
```
**What to point out:**
- The client connection times out because the firewall's default `FORWARD DROP` policy drops packets to `10.0.3.10:3306`.
- The browser on the host machine connects via `https://127.0.0.1:8443` through the client relay, crossing the firewall to reach Nginx TLS.

---

## ⏱️ Minute 3: Multi-Tier Nmap Security Scans
**Narrative:** *"We verify firewall enforcement using genuine Nmap port discovery scans executed from the client container across the router."*

```bash
# Run the automated cross-tier matrix verification
python lab.py verify
```
**What to point out:**
- In Mode A: Port `3306` on the database is `OPEN`. Ports `443` and `5000` are `FILTERED`.
- In Mode B: Port `3306` on the database is `FILTERED`. Port `443` on the web proxy is `OPEN`.
- In both modes: Management port `9099` on the firewall is `FILTERED` and non-reachable from tenant networks.

---

## ⏱️ Minute 4: Data Integrity & Price Tampering Demo
**Narrative:** *"Here is the critical security trade-off: in Two-Tier, authorization occurs only at the SQL grant level. The database cannot enforce domain pricing logic. In Three-Tier, server-side API middleware validates business rules."*

```bash
# Run the tamper demonstration
python lab.py tamper-demo
```
**What to point out:**
- **Mode A (Two-Tier):** Client executes `INSERT INTO invoice_items ... unit_price = 0.01` for a $499.50 monitor. The database commits it because `client_user` has `GRANT INSERT`. Data integrity is violated.
- **Mode B (Three-Tier):** Client sends the same $0.01 price to FastAPI. The API server verifies catalog pricing and rejects the request with `HTTP 400 Bad Request`.

---

## ⏱️ Minute 5: Wireshark Packet Dissection & PCAPs
**Narrative:** *"Packet captures are recorded live by `lab_sniffer` on the firewall's virtual network interfaces."*

```bash
# View captured live packets directly from the sniffer container
docker exec lab_sniffer tcpdump -nr /captures/live.pcap0 -c 15

# Demonstrate Mode A with TLS Disabled vs TLS Required
python lab.py tls-demo
```
**What to point out:**
- In unencrypted Mode A: Cleartext SQL queries (`SELECT id, sku, price...`) and credentials appear on the wire.
- In TLS Mode A: Port 3306 negotiates TLS 1.3 (`TLS_AES_256_GCM_SHA384`), proving plaintext is an administrator **configuration choice**, not an inherent flaw of Two-Tier.
- All per-interface `.pcap` files (`client.pcap0`, `web.pcap0`, `app.pcap0`, `db.pcap0`) are accessible in `./evidence/samples/`.
