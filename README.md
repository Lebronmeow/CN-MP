# Network Workbench v2 — Real Two-Tier vs Three-Tier Network Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose_v2-2496ED?logo=docker&logoColor=white)](file:///f:/CN-MP/docker-compose.yml)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](file:///f:/CN-MP/controller/main.py)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?logo=mysql&logoColor=white)](file:///f:/CN-MP/db/init.sql)
[![Nginx](https://img.shields.io/badge/Nginx-TLS_1.3-009639?logo=nginx&logoColor=white)](file:///f:/CN-MP/web/nginx.conf)
[![Tests Passing](https://img.shields.io/badge/Tests-100%25_Passing-success)](file:///f:/CN-MP/tests.js)

**Network Workbench v2** transforms an educational browser simulator into a fully realized, empirical computer networks laboratory. It deploys an authentic business application—**"ShopLedger"** (inventory management and billing)—across isolated Docker subnets governed by a stateful Linux `iptables` firewall router, complete with packet sniffing (`.pcap`), real Nmap port scans, Wireshark packet dissections, an active Controller API, and a dual-mode interactive dashboard.

---

## 1. Pedagogical Motivation & Architectural Context

### Teacher Feedback Addressed
Traditional network simulation tools often enforce a rigid narrative that direct client-to-database communication is inherently an invalid "security flaw" or "vulnerability", presenting a strict multi-tier chain (`Client → Web → App → DB`) as the only legitimate architecture.

In enterprise and industrial networking, **real networks are all connected, and direct client-to-database access is a legitimate, widely deployed architectural paradigm known as Two-Tier Client-Server Architecture.**

```
MODE A: Two-Tier Architecture (Client-Server)
+------------------------+                        +-----------------------+
|  ShopLedger CLI / TUI  | === TCP 3306 (MySQL) > |  Central MySQL Server |
|  192.168.1.20 (Client) |                        |  10.0.3.10 (Database) |
+------------------------+                        +-----------------------+
                \                                  /
                 ---> [ Stateful Firewall Router ] <---
                      Allows 192.168.1.0/24 -> 10.0.3.10:3306

MODE B: Three-Tier Architecture (Segmented Web-App-DB)
+------------------------+        +-----------------------+        +-----------------------+        +-----------------------+
|  Client Browser / Host | ==443> |  Nginx Reverse Proxy  | ==5000>|  FastAPI App Server   | ==3306>|  Central MySQL Server |
|  192.168.1.20 (Client) |        |  10.0.1.10 (Web)      |        |  10.0.2.10 (App)      |        |  10.0.3.10 (Database) |
+------------------------+        +-----------------------+        +-----------------------+        +-----------------------+
                \                      /            \                      /            \                      /
                 -------------------> [ Linux iptables Firewall Router ] <-------------------------------------
                      Policy: Default DROP. Allows only Client->Web, Web->App, App->DB.
```

### Real-World Production Precedents
1. **Two-Tier Client-Server (Mode A):**
   - **TallyPrime / Tally.ERP 9:** Accounting workstations in a LAN connecting directly to a dedicated Tally Server or SQL database host over local sockets.
   - **Point-of-Sale (POS) & Retail Terminals:** Supermarket checkouts and pharmacy terminals issuing direct SQL transactions against an on-premise database for minimal transaction latency.
   - **Hospital Information Systems (HIS):** Nurse stations, radiology workstations (PACS), and clinic terminals communicating directly with on-premise relational databases (e.g., Epic Hyperspace thick client, Cerner).
   - **Bloomberg Professional Terminal & SAP GUI:** Thick desktop workstations maintaining stateful client-to-server data sessions over dedicated enterprise networks.
   - **Factory SCADA & Industrial Control (ICS):** Embedded operational technology querying central telemetry historians directly.

2. **Three-Tier Architecture (Mode B):**
   - **Public E-Commerce & Internet Banking:** Web portals (Amazon, banking apps) where thousands of untrusted, anonymous public clients connect over TLS. Direct database access is blocked to prevent database exposure and centralize business logic, rate limiting, and authorization.

---

## 2. Architectural Comparison & Trade-Offs

| Evaluation Vector | Mode A: Two-Tier Client-Server | Mode B: Three-Tier Architecture |
| :--- | :--- | :--- |
| **Primary Topology** | Thick Client $\to$ Central Database Server (`:3306`) | Client $\to$ Web Proxy (`:443`) $\to$ App API (`:5000`) $\to$ Database (`:3306`) |
| **Network Attack Surface** | Database port `:3306` directly reachable from client subnet. Database must enforce user-level privilege separation. | Zero client access to database or application layers. DB isolated deep in a protected backend subnet. |
| **Measured Latency (Reuse)** | **$0.21\,\text{ms}$ Median** (P95: $0.29\,\text{ms}$) — **$21.9\times$ faster** round-trip time. | **$4.59\,\text{ms}$ Median** (P95: $5.67\,\text{ms}$) — Multi-hop TCP dispatch, TLS crypto, and JSON parsing. |
| **Measured Latency (New Conn)** | **$1.14\,\text{ms}$ Median** (P95: $1.50\,\text{ms}$) — **$7.7\times$ faster** setup. | **$8.72\,\text{ms}$ Median** (P95: $9.33\,\text{ms}$) — Full TLS 1.3 handshake + HTTP parsing. |
| **Credential Distribution** | Database credentials (`client_user`) reside on client machines/executables. Compromise of a client terminal yields DB access. | Database credentials (`app_user`) reside solely in protected application tier environment. Clients only hold session tokens. |
| **Business Logic Layer** | Logic embedded in client applications. SQL table/column grants cannot enforce domain price invariants (see Tamper Demo). | Centralized in application service (FastAPI). Server validates input against catalog before database commits. |
| **Transport Encryption** | Raw MySQL client-server protocol. **Plaintext or TLS is a configuration choice** (`SHOW STATUS LIKE 'Ssl_cipher'`). | Modern TLS 1.3 encryption terminates at edge (`nginx`). Centralized API access logs and CloudTrail-style audit points. |
| **Scalability & Pooling** | Every active client opens dedicated MySQL connections; MySQL connection limits (typically 151–1,000) bound client scaling. | Application tier pools database connections (SQLAlchemy/connection pools); supports millions of stateless HTTP clients. |
| **Ideal Deployment Environment** | Trusted private LANs, high-frequency internal data entry, small business accounting, medical clinics. | Internet-facing web applications, cloud SaaS platforms, untrusted public environments, zero-trust enterprise perimeters. |

---

## 3. Real Network Topology & Docker Compose Subnets

The lab recreates the exact subnets and IP addresses from the educational workbench on isolated Docker bridge networks.

```
                                  +---------------------------------------+
                                  |     lab_firewall (Alpine Linux)       |
                                  |     IP Forwarding: ON (Router)        |
                                  |     Policy: Default DROP FORWARD      |
                                  +---------------------------------------+
                                  /         |                 |          \
                 192.168.1.254   /          | 10.0.1.254      | 10.0.2.254\ 10.0.3.254
                                /           |                 |            \
             client_net        /    web_net |         app_net |     db_net  \
           192.168.1.0/24     /  10.0.1.0/24|      10.0.2.0/24|   10.0.3.0/24\
                             /              |                 |               \
                +-----------------+  +---------------+ +---------------+ +---------------+
                |   lab_client    |  |    lab_web    | |    lab_app    | |    lab_db     |
                |  (Python/TUI)   |  | (Nginx TLS)   | |   (FastAPI)   | |  (MySQL 8.0)  |
                |  192.168.1.20   |  |  10.0.1.10    | |  10.0.2.10    | |  10.0.3.10    |
                +-----------------+  +---------------+ +---------------+ +---------------+
```

### Subnet Specification
All application networks are designated `internal: true` in [`docker-compose.yml`](file:///f:/CN-MP/docker-compose.yml), preventing containers from bypassing the firewall router via Docker's default host bridge gateway:

1. **`client_net` (`192.168.1.0/24`):**
   - Container: `lab_client` (`192.168.1.20`)
   - Gateway / Router Interface: `192.168.1.254`
   - Ingress Relay: Listens strictly on `127.0.0.1:8443` on the host, relaying browser requests through the client's network stack to the firewall router.
2. **`web_net` (`10.0.1.0/24`):**
   - Container: `lab_web` (`10.0.1.10`)
   - Service: Nginx with self-signed TLS certificate (Port `443`), reverse proxying `/api/` to `lab_app:5000`.
   - Gateway / Router Interface: `10.0.1.254`
3. **`app_net` (`10.0.2.0/24`):**
   - Container: `lab_app` (`10.0.2.10`)
   - Service: Python 3.11 / FastAPI REST service (Port `5000`) executing business logic and parameterized SQL queries.
   - Gateway / Router Interface: `10.0.2.254`
4. **`db_net` (`10.0.3.0/24`):**
   - Container: `lab_db` (`10.0.3.10`)
   - Service: Oracle MySQL Community Server 8.0 (Port `3306`).
   - Gateway / Router Interface: `10.0.3.254`
5. **`mgmt_net` (`172.28.0.0/24`):**
   - Dedicated management network connecting the host Controller API (`172.28.0.1`) to the firewall control daemon (`172.28.0.254:9099`).
   - Completely inaccessible from client, web, app, or database subnets.

### Stateful Firewall & Security
The firewall container (`lab_firewall`) runs Alpine Linux with `NET_ADMIN` capabilities and kernel IP forwarding enabled (`net.ipv4.ip_forward=1`).
- **Stateful Connection Tracking:** Inspects TCP flags and allows return packets via `ctstate RELATED,ESTABLISHED`.
- **Mode Switching:** Rules are defined in clean bash scripts:
  - [`firewall/rules/mode-a.sh`](file:///f:/CN-MP/firewall/rules/mode-a.sh): Mode A (Client $\to$ DB `:3306` ALLOW).
  - [`firewall/rules/mode-b.sh`](file:///f:/CN-MP/firewall/rules/mode-b.sh): Mode B (Client $\to$ Web `:443`, Web $\to$ App `:5000`, App $\to$ DB `:3306` ALLOW; inter-tier bypasses DENIED).
  - [`firewall/rules/mode-custom.sh`](file:///f:/CN-MP/firewall/rules/mode-custom.sh): Mode C (Dynamic custom rules).
- **Control Daemon (`fw_daemon.py`):** Binds strictly to `172.28.0.254:9099` on `mgmt_net`, protected by shared bearer token authentication (`FW_TOKEN`). All other tiers attempting to contact `:9099` are rejected by the `INPUT` chain.

### Packet Sniffing (`lab_sniffer`)
The packet sniffer container (`lab_sniffer`) attaches to the firewall's network namespace (`network_mode: "service:firewall"`), running rotating `tcpdump` instances writing standard pcap files to [`captures/`](file:///f:/CN-MP/captures):
- `live.pcap0`: Aggregate capture across all active interfaces.
- `client.pcap0`: Native Ethernet capture on interface `eth1` (`client_net`).
- `web.pcap0`: Native Ethernet capture on interface `eth2` (`web_net`).
- `app.pcap0`: Native Ethernet capture on interface `eth3` (`app_net`).
- `db.pcap0`: Native Ethernet capture on interface `eth4` (`db_net`).
- Sanitized sample pcaps are committed to [`evidence/samples/`](file:///f:/CN-MP/evidence/samples) for static/Vercel downloads.

---

## 4. "ShopLedger" Application & Database Schema

Both Mode A and Mode B operate over the exact same schema and dataset defined in [`db/init.sql`](file:///f:/CN-MP/db/init.sql).

### Realistic Dataset
- **50 Products:** SKUs, category classifications, unit prices, and stock inventory.
- **20 Customers:** Commercial and retail accounts across various cities.
- **100 Invoices & Line Items:** Historical sales transactions totaling over \$128,000.
- **Transactional Stock Decrementing:** Invoice creation runs in atomic `START TRANSACTION ... COMMIT` blocks to prevent negative inventory.

### Least-Privilege Database Users
To demonstrate real security controls at the data layer, three separate database users are provisioned:
1. **`client_user`:**
   - Strictly restricted to `SELECT` on `products` and `customers`, `UPDATE (stock)` on `products`, and `SELECT, INSERT` on `invoices` and `invoice_items`.
   - **No DDL privileges:** Cannot `DROP`, `ALTER`, or `CREATE` tables.
   - **No administrative access:** Zero access to `mysql.*` or user management tables.
2. **`app_user`:**
   - Full CRUD (`SELECT, INSERT, UPDATE, DELETE`) on the `shopledger` business tables.
   - Used exclusively by the FastAPI application service in Mode B.
3. **`admin_user`:**
   - Full administrative database access, reserved solely for maintenance and initial migrations; never used by application or client workloads.

---

## 5. Controller API & Security Hardening

The Controller service ([`controller/main.py`](file:///f:/CN-MP/controller/main.py)) runs on `127.0.0.1:8080`, providing a clean, validated bridge between the web dashboard and the container lab:

- **Host-Header Allowlist:** Protects against DNS rebinding attacks by allowing only `localhost` and `127.0.0.1`.
- **Token-Authenticated Mutating Endpoints:** Changing modes (`POST /mode`) or applying rules (`POST /rules/custom`) requires the `X-Lab-Token` header (`LAB_CONTROLLER_TOKEN`).
- **Telemetry & Probing Architecture:**
  - **`/status`:** Queries Docker daemon lifecycle status and inspects firewall counters via the isolated `mgmt_net` interface (`172.28.0.254:9099`).
  - **`/probe`:** Issues `docker exec` against the designated source container (`lab_client`, `lab_web`) with strict argument lists (no shell interpolation). The probe packet originates inside the container's network namespace and routes across the firewall router, recording RTT and matching rule counters.

---

## 6. Empirical Benchmarks & Evidence

All benchmark measurements are 100% reproducible and generated via [`evidence/run_all.py`](file:///f:/CN-MP/evidence/run_all.py).

### Latency Benchmark (100 Iterations, Warm-Up Dropped)
Evaluating 100 identical product queries after dropping 5 initial warm-up runs:

```
================================================================================
                    EMPIRICAL PERFORMANCE BENCHMARK REPORT
================================================================================
Profile 1: Persistent Connection Reuse (MySQL socket vs HTTPS Keep-Alive)
Metric                       Mode A (Two-Tier)           Mode B (Three-Tier)
--------------------------------------------------------------------------------
Sample Size                  100 iterations              100 iterations
Min Latency                  0.20 ms                     4.07 ms
Mean Latency                 0.23 ms                     4.68 ms
Median (P50) Latency         0.21 ms                     4.59 ms
95th Percentile (P95)        0.29 ms                     5.67 ms
Max Latency                  0.53 ms                     6.03 ms
Std Deviation                0.05 ms                     0.41 ms
--------------------------------------------------------------------------------
SPEEDUP FACTOR:              Two-Tier is 21.86x FASTER (Median) / 20.35x (Mean)

Profile 2: Per-Request Connection Establishment (New TCP socket each time)
Metric                       Mode A (Two-Tier)           Mode B (Three-Tier)
--------------------------------------------------------------------------------
Sample Size                  100 iterations              100 iterations
Min Latency                  0.94 ms                     7.87 ms
Mean Latency                 1.21 ms                     8.86 ms
Median (P50) Latency         1.14 ms                     8.72 ms
95th Percentile (P95)        1.50 ms                     9.33 ms
Max Latency                  2.33 ms                     9.80 ms
Std Deviation                0.22 ms                     0.47 ms
--------------------------------------------------------------------------------
SPEEDUP FACTOR:              Two-Tier is 7.65x FASTER (Median) / 7.09x (Mean)
================================================================================
```

#### Benchmark Limitations Note:
1. **Single-Host Environment:** Containers communicate across Linux bridge subnets on one physical machine; WAN latency (15–100 ms) is not simulated.
2. **Payload Size:** The benchmark query fetches 5 product rows; network protocol overhead dominates over database disk I/O.
3. **Sequential Concurrency:** Serialized execution ($c = 1$) does not measure MySQL connection pool exhaustion under high concurrency ($c > 500$), where Mode B's connection pooling excels.

---

## 7. Security Demonstrations & Audits

### A. Two-Tier TLS Demonstration (`python lab.py tls-demo`)
Proves that cleartext on port 3306 is an administrator/client **configuration choice**, not an inherent flaw of Two-Tier architecture:
```text
--- [1] Mode A with TLS Disabled (Plaintext) ---
  Transport Cipher : NONE (Plaintext Wire Traffic)
  TLS Version      : NONE

--- [2] Mode A with TLS Required (Encrypted) ---
  Transport Cipher : TLS_AES_256_GCM_SHA384
  TLS Version      : TLSv1.3
```

### B. Stock Decrement & Price Tampering Demo (`python lab.py tamper-demo`)
Demonstrates the fundamental architectural security trade-off:
- **Mode A (Two-Tier):** Client executes `INSERT INTO invoice_items ... unit_price = 0.01`. The database allows the insert because `client_user` has `GRANT INSERT ON invoice_items`. **SQL table privileges cannot evaluate application business rules.**
- **Mode B (Three-Tier):** Client submits `unit_price: 0.01` to FastAPI. The API server detects the discrepancy against `products.price` and **rejects the tampering with HTTP 400 Bad Request** before any database write occurs.

### C. Secrets Scan & Git History Verification
- Verified that `history.db` was **never committed** to Git.
- Audited with [`scripts/secrets_scan.py`](file:///f:/CN-MP/scripts/secrets_scan.py); all credentials reside in `.env`.

---

## 8. Dashboard: Live vs. Recorded Mode

The evolved dashboard ([`index.html`](file:///f:/CN-MP/index.html), [`style.css`](file:///f:/CN-MP/style.css), [`script.js`](file:///f:/CN-MP/script.js)) runs seamlessly in two distinct modes:

1. **LIVE Mode (Local Lab Attached):**
   - Connects to Controller API on `http://127.0.0.1:8080`.
   - Live Mode badge glows emerald green.
   - Probing triggers actual network packets across the Docker containers.
   - Live packet and byte counters update from kernel `iptables` counters in real time.
2. **RECORDED Mode (Vercel / Static Deployment):**
   - Deployed at [`cnmp.vercel.app`](https://cnmp.vercel.app).
   - Operates with **zero backend dependencies**, replaying authentic committed measurements from [`evidence/recorded_data.json`](file:///f:/CN-MP/evidence/recorded_data.json).
   - PCAP download links serve committed sample pcaps from [`evidence/samples/`](file:///f:/CN-MP/evidence/samples).

---

## 9. Quickstart & Verification Guide

### 1. Launch the Lab
```bash
# Clone repository and switch to lab-v2 branch
git clone https://github.com/Lebronmeow/CN-MP.git
cd CN-MP
git checkout lab-v2

# Start the lab containers
python lab.py start
```

### 2. Run the Verification Suite & Demos
```bash
# Run multi-tier firewall verification matrix (14 tests per mode)
python lab.py verify

# Run TLS disabled vs TLS required demonstration
python lab.py tls-demo

# Run stock decrement and price tampering demonstration
python lab.py tamper-demo

# Run unit tests
npm test
```

### 3. Run Benchmarks & Controller
```bash
# Run the empirical benchmark pipeline
python evidence/run_all.py

# Launch the Controller API daemon
python lab.py controller

# In another terminal, view the dashboard:
python -m http.server 8000
# Open http://localhost:8000 in your browser
```

---

## 10. Documentation Index (`docs/`)

Comprehensive technical references are maintained in [`docs/`](file:///f:/CN-MP/docs):
- [`docs/architecture.md`](file:///f:/CN-MP/docs/architecture.md): Deep dive into Two-Tier vs Three-Tier network topologies, subnet routing, and relay proxies.
- [`docs/benchmarks.md`](file:///f:/CN-MP/docs/benchmarks.md): Benchmark methodology, warm-up drops, connection reuse profiles, and limitations.
- [`docs/security-audit.md`](file:///f:/CN-MP/docs/security-audit.md): Least privilege SQL grants, secrets scan findings, Host-header validation, and price tampering analysis.
- [`docs/firewall-rules.md`](file:///f:/CN-MP/docs/firewall-rules.md): Stateful filtering, conntrack, per-mode iptables rulesets, and management daemon isolation.
- [`docs/wireshark-recipes.md`](file:///f:/CN-MP/docs/wireshark-recipes.md): Packet captures guide, per-interface packet dissections, and Wireshark display filter recipes.

---

## 11. Academic Integrity & Citations

- **Curriculum:** Computer Networks (CN) Mini-Project.
- **Architectural Reference:** Silberschatz, Korth, Sudarshan — *Database System Concepts* (Multi-tier architectures).
- **Network Security Reference:** Cheswick, Bellovin, Rubin — *Firewalls and Internet Security: Repelling the Wily Hacker*.
- **Standard Protocol References:** RFC 8446 (TLS 1.3), RFC 793 (TCP), RFC 792 (ICMP).
- **License:** [MIT License](file:///f:/CN-MP/LICENSE)
