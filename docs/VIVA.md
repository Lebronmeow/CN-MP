# 25 Viva Examination Questions & Answers

High-yield oral exam Q&As covering computer networks, firewall design, network topologies, and empirical security engineering.

---

### Q1: Is a Docker firewall a real firewall?
**Answer:** Yes. In Linux, a firewall is implemented in the kernel using the `netfilter` subsystem, configured via `iptables` or `nftables`. A Docker container with `cap_add: NET_ADMIN` operates in its own Linux network namespace with kernel packet filtering enabled. It intercepts genuine Layer 3/4 frames crossing virtual Ethernet (`veth`) interfaces between bridge subnets, enforces stateful connection tracking (`conntrack`), and applies real routing rules identical to a standalone hardware or VM router.

---

### Q2: Why is the latency different between Mode A and Mode B?
**Answer:**
1. **Hop Count:** Mode A traverses 1 virtual router hop directly to MySQL. Mode B traverses 3 virtual router hops (Client $\to$ Web $\to$ App $\to$ DB).
2. **Crypto & Handshakes:** Mode B terminates TLS 1.3 (ECDHE asymmetric key negotiation and symmetric AES-GCM decryption).
3. **Application Stack:** Mode A reads compact binary MySQL protocol frames directly. Mode B incurs Nginx reverse-proxy socket dispatch, FastAPI ASGI routing, Pydantic schema validation, and JSON serialization.
- Measured: Persistent reuse is **$21.9\times$ faster** in Two-Tier (0.21 ms vs 4.59 ms median); per-request connection is **$7.7\times$ faster** (1.14 ms vs 8.72 ms median).

---

### Q3: Which real applications legitimately use direct database access (Two-Tier)?
**Answer:**
- **LAN Accounting Software:** TallyPrime / Tally.ERP 9 multi-user LAN deployments.
- **Retail & Supermarket Point-of-Sale (POS):** Dedicated checkout terminals executing direct transactions against an on-premise SQL server.
- **Hospital Information Systems (HIS):** Nurse and clinical terminal workstations (e.g. Epic Hyperspace, Cerner) querying enterprise database clusters.
- **Financial & Trading Terminals:** Bloomberg Professional Terminal and SAP GUI desktop clients connecting to private backend data engines.
- **Factory SCADA & ICS:** Operational technology terminals reading real-time telemetry from central historians.

---

### Q4: What is the fundamental difference between Two-Tier and Three-Tier architectures?
**Answer:** In Two-Tier (Client-Server), the user interface and business logic reside directly on the client machine, communicating directly with the database. In Three-Tier, the user interface (Tier 1), business logic server (Tier 2), and database storage (Tier 3) are physically separated across independent network tiers, preventing clients from ever communicating directly with the database.

---

### Q5: Why are the Docker subnets configured with `internal: true`?
**Answer:** By default, Docker creates a bridge gateway on the host that provides inter-container routing and NAT internet access. Marking networks `internal: true` removes the default host gateway, ensuring containers cannot bypass the firewall. The only route out of each subnet is through the firewall router (`192.168.1.254`, `10.0.1.254`, etc.).

---

### Q6: How does the firewall container act as a router between subnets?
**Answer:** The firewall container has kernel IP forwarding enabled (`net.ipv4.ip_forward = 1`) and has virtual network interfaces attached to all 5 isolated subnets. When a container sends a packet to an IP outside its own `/24` subnet, its default route forwards the frame to the firewall's interface, where the kernel evaluates `iptables` FORWARD rules before routing the packet to the destination subnet.

---

### Q7: What is a stateful firewall and how does `conntrack` work?
**Answer:** A stateful firewall tracks the operational state of network connections (TCP flags, sequence numbers, ICMP identifiers) in kernel memory via `conntrack`. The rule `-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT` automatically permits return reply packets for established outbound connections without requiring reverse firewall holes to be opened.

---

### Q8: Why is the default policy of the firewall set to `FORWARD DROP`?
**Answer:** The principle of default deny (zero-trust): any traffic not explicitly matched and approved by an allow rule must be dropped. This prevents inadvertent data leaks, unauthorized inter-tier lateral movement, and bypass attacks.

---

### Q9: What happens to packets that do not match an explicit `ACCEPT` rule?
**Answer:** They match the final rules in the `FORWARD` chain: a rate-limited logging rule (`-m limit --limit 5/min -j LOG --log-prefix "[FW-DROP] "`) logs the source, destination, and ports to kernel `dmesg`, and the packet is silently discarded by `-j DROP`.

---

### Q10: How does Nmap distinguish between `open`, `closed`, and `filtered` ports?
**Answer:**
- **Open:** Target responds with `SYN/ACK` (TCP handshake accepted).
- **Closed:** Target responds with `RST` (port is reachable, but no application is listening).
- **Filtered:** Target sends no response, or firewall returns an ICMP Type 3 (Destination Unreachable) packet. The probe packet was dropped by a firewall filter.

---

### Q11: Why is direct client access to MySQL considered a risk in public web environments?
**Answer:** In public internet environments, clients are anonymous, untrusted, and potentially malicious. Exposing MySQL directly exposes database authentication vulnerabilities, requires distributing database credentials to end-user machines, allows denial-of-service via connection pool exhaustion, and prevents enforcing centralized business rules.

---

### Q12: How does least privilege apply to database users in this lab?
**Answer:**
- `client_user`: Restricted to `SELECT` on products/customers, `UPDATE (stock)` on products, and `INSERT` on invoices. Cannot DROP tables, alter schemas, or query `mysql.user`.
- `app_user`: CRUD on application tables only.
- `admin_user`: Local administrative management only; never exposed to client or application tiers.

---

### Q13: How does `client_user` decrement inventory stock without full table `UPDATE` permissions?
**Answer:** MySQL supports column-level privilege grants. In [`db/init.sql`](file:///f:/CN-MP/db/init.sql), `client_user` is granted:
```sql
GRANT UPDATE (stock) ON shopledger.products TO 'client_user'@'%';
```
The client can execute `UPDATE products SET stock = stock - 1 WHERE id = ?`, but is forbidden from updating prices, names, or categories.

---

### Q14: What does the "Price Tampering Demo" prove about SQL grants vs application logic?
**Answer:** It demonstrates that database privilege systems are authorization controls, **not domain business invariant validators**. In Mode A, `client_user` has `GRANT INSERT ON invoice_items`, so the database permits inserting a $499.50 monitor with a manipulated price of $0.01. In Mode B, the FastAPI middleware validates input against the trusted server catalog and rejects the manipulated price with `HTTP 400 Bad Request`.

---

### Q15: Is plaintext wire transmission inherent to Two-Tier architecture?
**Answer:** No. Plaintext on port 3306 is an administrator/client **configuration choice**. In [`lab.py tls-demo`](file:///f:/CN-MP/evidence/tls_demo.py), we prove that MySQL natively supports TLS 1.3 (`TLS_AES_256_GCM_SHA384`). Two-Tier networks can mandate TLS encryption between desktop clients and database servers.

---

### Q16: How does TLS 1.3 encryption protect Mode B web traffic?
**Answer:** TLS 1.3 encrypts application data using symmetric ciphers (e.g. `AES-256-GCM`) established via ephemeral Diffie-Hellman key exchange (`ECDHE`). Packet sniffers on the wire observe only encrypted application records (`tls.record.content_type == 23`); HTTP headers, URIs, credentials, and JSON payloads remain confidential.

---

### Q17: What is a DMZ (Demilitarized Zone) and which container represents it?
**Answer:** A DMZ is a semi-trusted perimeter subnetwork separating an internal private network from untrusted clients. In this lab, `web_net` (`10.0.1.0/24`) running `lab_web` (Nginx) represents the DMZ. It is exposed to the client network on port 443, but cannot query the database directly; it can only proxy requests to the application server on port 5000.

---

### Q18: How does the host machine reach the isolated Nginx container without bypassing the firewall?
**Answer:** The client container (`lab_client`) runs a local ingress relay binding strictly to `127.0.0.1:8443` on the host. When a host browser visits `https://127.0.0.1:8443`, the packet enters the client's network stack and routes through the firewall (`192.168.1.254`) to Nginx (`10.0.1.10:443`). In Mode B, the firewall permits it; in Mode A, it drops it.

---

### Q19: What is DNS rebinding, and how does the Controller API protect against it?
**Answer:** In a DNS rebinding attack, a malicious website resolves an external domain to `127.0.0.1`, tricking the victim's browser into making requests to local services. The Controller API defends against this using a Host-header allowlist middleware that rejects any request whose `Host` header is not `localhost` or `127.0.0.1`.

---

### Q20: Why do mutating Controller API endpoints require token authentication?
**Answer:** Endpoints that change firewall modes (`POST /mode`) or apply custom rules (`POST /rules/custom`) modify the host's kernel firewall state. Requiring an `X-Lab-Token` header prevents unauthorized local scripts, cross-origin browser scripts, or CSRF attacks from reconfiguring network policies.

---

### Q21: How do `/status` and `/probe` reach the containers without compromising isolation?
**Answer:**
- **`/status`:** Queries container states via local Docker daemon socket (`docker ps`), and queries firewall counters over the isolated `mgmt_net` (`172.28.0.254:9099`) with shared token auth. Tenant subnets cannot reach `:9099`.
- **`/probe`:** Uses `docker exec` with parameter arrays (no shell interpolation) to run `nc` or `ping` inside the source container namespace. The probe packet traverses real network interfaces and the firewall router.

---

### Q22: What are the key limitations of the latency benchmark measurements?
**Answer:**
1. Tests ran across virtual bridges on a single physical host; WAN latency (15–100 ms) and routing jitter are absent.
2. The payload was fixed to 5 product rows (~400 bytes), so network protocol overhead dominated over database disk I/O.
3. Concurrency was serialized ($c = 1$). It does not simulate MySQL connection pool exhaustion under hundreds of concurrent clients.

---

### Q23: Why does Three-Tier scale better under high concurrent user loads despite higher single-request latency?
**Answer:** In Two-Tier, every client holds an active, persistent TCP connection to MySQL. Because MySQL creates a dedicated thread per connection, servers exhaust memory and connection limits (`max_connections = 151` default) at modest scales. Three-Tier multiplexes thousands of stateless HTTP clients across a fixed pool of persistent database connections maintained by the application tier.

---

### Q24: What role does ICMP play in network diagnostics like `ping` and `traceroute`?
**Answer:**
- `ping`: Uses ICMP Type 8 (Echo Request) and Type 0 (Echo Reply) to measure Layer 3 reachability and round-trip time.
- `traceroute`: Sends packets with incrementing TTL (Time-To-Live) values. Each intermediate router decrements TTL to 0 and returns an ICMP Type 11 (Time Exceeded) packet, revealing the path taken across the network.

---

### Q25: What Wireshark display filter would you use to isolate MySQL queries and TLS handshakes?
**Answer:**
- **MySQL Queries:** `tcp.port == 3306 && mysql.query`
- **TLS Handshakes:** `tcp.port == 443 && tls.handshake.type == 1` (Client Hello)
- **Firewall Drops:** `tcp.flags.syn == 1 && tcp.flags.ack == 0` (SYN without ACK indicates dropped connection attempts).
