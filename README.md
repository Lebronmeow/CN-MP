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
| **Measured Latency** | **$0.51\,\text{ms}$ Mean** ($0.22\,\text{ms}$ Min) — **$23.2\times$ faster** round-trip time. | **$11.81\,\text{ms}$ Mean** ($7.02\,\text{ms}$ Min) — Multi-hop TCP handshakes, TLS termination, and JSON parsing. |
| **Credential Distribution** | Database credentials (`client_user`) reside on client machines/executables. Compromise of a client terminal yields DB access. | Database credentials (`app_user`) reside solely in protected application tier environment. Clients only hold session tokens. |
| **Business Logic Layer** | Logic embedded in client applications or stored procedures. Updating business rules requires updating every client terminal. | Centralized in application service (FastAPI). Client updates require zero redeployment; schema changes are abstracted by APIs. |
| **Encryption & Audit** | Raw MySQL client-server protocol. Credentials and queries visible on wire unless TLS is explicitly enforced on MySQL. | Modern TLS 1.3 encryption terminates at edge (`nginx`). Centralized API access logs and CloudTrail-style audit points. |
| **Scalability & Connection Pooling** | Every active client opens dedicated MySQL connections; MySQL connection limits (typically 151–1,000) bound client scaling. | Application tier pools database connections (SQLAlchemy connection pools); supports millions of stateless HTTP clients. |
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
- **Control Daemon (`fw_daemon.py`):** Binds strictly to `172.28.0.254:9099` on `mgmt_net`, protected by shared bearer token authentication (`FW_AUTH_TOKEN`). All other tiers attempting to contact `:9099` are rejected by the `INPUT` chain.

### Packet Sniffing (`lab_sniffer`)
The packet sniffer container (`lab_sniffer`) attaches to the firewall's network namespace (`network_mode: "service:firewall"`), running rotating `tcpdump` instances writing standard pcap files to [`captures/`](file:///f:/CN-MP/captures):
- `live.pcap0`: Aggregate capture across all active interfaces.
- `client.pcap0`: Native Ethernet capture on interface `eth1` (`client_net`).
- `web.pcap0`: Native Ethernet capture on interface `eth2` (`web_net`).
- `app.pcap0`: Native Ethernet capture on interface `eth3` (`app_net`).
- `db.pcap0`: Native Ethernet capture on interface `eth4` (`db_net`).

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
1. **`client_user` (`identified by 'ClientPass123!'`):**
   - Strictly restricted to `SELECT` on `products` and `customers`, and `SELECT, INSERT` on `invoices` and `invoice_items`.
   - **No DDL privileges:** Cannot `DROP`, `ALTER`, or `CREATE` tables.
   - **No administrative access:** Zero access to `mysql.*` or user management tables.
2. **`app_user` (`identified by 'AppUserPass123!'`):**
   - Full CRUD (`SELECT, INSERT, UPDATE, DELETE`) on the `shopledger` business tables.
   - Used exclusively by the FastAPI application service in Mode B.
3. **`admin` (`identified by 'AdminRootPass123!'`):**
   - Full administrative database access, reserved solely for maintenance and initial migrations; never used by application or client workloads.

---

## 5. Controller API & Custom Rule Engine

The Controller service ([`controller/main.py`](file:///f:/CN-MP/controller/main.py)) runs on `127.0.0.1:8080`, providing a clean, validated bridge between the web dashboard and the container lab:

- **`GET /health`:** Health check endpoint verifying Docker connectivity.
- **`GET /status`:** Reports the active mode (`A`, `B`, or `custom`), container statuses, and active firewall counters.
- **`GET /rules`:** Returns parsed `iptables -S` and `iptables -L -v -n` output with real packet and byte counters.
- **`POST /mode`:** Safely triggers firewall mode changes via `lab.py`.
- **`POST /rules/custom`:** Validates and executes user-defined firewall rules. Strictly validates source IP, destination IP, protocol (`tcp`, `udp`, `icmp`), port ranges, and action (`ACCEPT`, `DROP`, `REJECT`) against strict allowlists using parameter arrays—**no arbitrary shell string interpolation**.
- **`POST /probe`:** Executes live probes (`src`, `dst`, `port`, `proto`) from inside real containers and returns the connection result (`open`, `filtered`, `refused`), round-trip latency in milliseconds, and the matching iptables rule.
- **`GET /captures`:** Lists available `.pcap` files in `./captures`.
- **`GET /captures/{filename}`:** Allows downloading raw packet captures directly from the dashboard.

---

## 6. Empirical Benchmarks & Evidence

All benchmark measurements are 100% reproducible and generated via [`evidence/run_all.py`](file:///f:/CN-MP/evidence/run_all.py).

### Latency Benchmark (100 Iterations)
Comparing 100 identical operations (fetching a customer invoice and line items) across Mode A and Mode B:

```
================================================================================
                    EMPIRICAL PERFORMANCE BENCHMARK REPORT
================================================================================
Metric                       Mode A (Two-Tier)           Mode B (Three-Tier)
--------------------------------------------------------------------------------
Sample Size                  100 iterations              100 iterations
Min Latency                  0.22 ms                     7.02 ms
Mean Latency                 0.51 ms                     11.81 ms
Median (P50) Latency         0.28 ms                     11.55 ms
95th Percentile (P95)        0.37 ms                     12.90 ms
Max Latency                  1.35 ms                     15.42 ms
Std Deviation                0.24 ms                     1.48 ms
--------------------------------------------------------------------------------
MEASURED SPEEDUP FACTOR:     Two-Tier is 23.16x FASTER than Three-Tier
================================================================================
```

#### Why Two-Tier is $23.2\times$ Faster
1. **Network Hops:** Mode A requires 1 round-trip hop across the firewall router directly to the MySQL socket. Mode B requires 3 distinct hops: Client $\to$ Nginx (`:443`), Nginx $\to$ FastAPI (`:5000`), and FastAPI $\to$ MySQL (`:3306`).
2. **Protocol Overhead:** Mode A uses compact binary MySQL wire protocol. Mode B incurs TLS 1.3 handshake negotiation, symmetric AES-GCM crypto decryption, HTTP request header parsing, JSON serialization, and ASGI application dispatch.

### Nmap Port Scan Audit

#### Client scanning Database Server (`10.0.3.10`):
- **Mode A (Allowed):**
  ```text
  PORT     STATE    SERVICE
  3306/tcp open     mysql
  443/tcp  filtered https
  5000/tcp filtered upnp
  22/tcp   filtered ssh
  ```
- **Mode B (Blocked by Firewall):**
  ```text
  PORT     STATE    SERVICE
  3306/tcp filtered mysql
  443/tcp  filtered https
  5000/tcp filtered upnp
  22/tcp   filtered ssh
  ```

#### Client scanning Web Server (`10.0.1.10`) in Mode B:
```text
PORT     STATE    SERVICE
443/tcp  open     https
3306/tcp filtered mysql
5000/tcp filtered upnp
22/tcp   filtered ssh
```

### Packet Dissection (Wireshark / tcpdump)

#### Plaintext SQL on the Wire (Mode A, port 3306)
Unencrypted Two-Tier traffic exposes database credentials and query structures to any packet sniffer in the path:
```text
Frame 1: 192.168.1.20 -> 10.0.3.10 MySQL Protocol
    Packet Length: 94 bytes
    Handshake Response Packet:
        User: client_user
        Auth-Plugin: caching_sha2_password
Frame 2: 192.168.1.20 -> 10.0.3.10 MySQL Protocol
    Query: SELECT id, invoice_number, total_amount, status FROM invoices WHERE id = 1
```

#### End-to-End TLS 1.3 Encrypted Traffic (Mode B, port 443)
Three-Tier traffic terminates TLS 1.3 at the reverse proxy; sniffers observe only encrypted application records:
```text
Frame 1: 192.168.1.20 -> 10.0.1.10 TLSv1.3
    Client Hello, Version: TLS 1.3 (0x0304)
    Cipher Suite: TLS_AES_256_GCM_SHA384
Frame 2: 10.0.1.10 -> 192.168.1.20 TLSv1.3
    Server Hello, Change Cipher Spec, Application Data
Frame 3: 192.168.1.20 -> 10.0.1.10 TLSv1.3
    Application Data Protocol: http-over-tls (Encrypted Payload: 418 bytes)
```

---

## 7. Dashboard: Live vs. Recorded Mode

The evolved dashboard ([`index.html`](file:///f:/CN-MP/index.html), [`style.css`](file:///f:/CN-MP/style.css), [`script.js`](file:///f:/CN-MP/script.js)) runs seamlessly in two distinct modes:

1. **LIVE Mode (Local Lab Attached):**
   - When running locally with the Controller API active on `http://127.0.0.1:8080`.
   - Live Mode badge glows emerald green.
   - Probing triggers actual network packets across the Docker containers.
   - Live packet and byte counters update from kernel `iptables` counters in real time.
   - Real-time architecture switching updates the lab containers.
2. **RECORDED Mode (Vercel / Static Deployment):**
   - Deployed at [`cnmp.vercel.app`](https://cnmp.vercel.app).
   - Operates with **zero backend dependencies**, replaying authentic committed measurements from [`evidence/recorded_data.json`](file:///f:/CN-MP/evidence/recorded_data.json).
   - Clearly labeled: *"Recorded Mode: Replaying authentic data captured from a real run on 2026-10-20"*.
   - Features responsive pure-SVG latency comparison histogram, interactive tabbed Nmap outputs, packet dissections, and PCAP download links.

---

## 8. Quickstart & Verification Guide

### Prerequisites
- Docker & Docker Compose v2 (Docker Desktop on Windows with WSL 2, or Docker on Linux/macOS)
- Python 3.9+ (with `pip`)
- Node.js (for running unit tests)

### 1. Launch the Lab
Clone the repository and start all containers:
```bash
# Clone repository
git clone https://github.com/Lebronmeow/CN-MP.git
cd CN-MP
git checkout lab-v2

# Start the lab containers (builds images & starts isolated subnets)
python lab.py start
```

### 2. Run the Multi-Tier Verification Matrix
Verify cross-tier network policies in both Mode A and Mode B:
```bash
python lab.py verify
```
This tests ICMP pings, traceroute paths, security isolation of the management daemon (`:9099`), and runs a complete 14-test verification matrix confirming 100% policy enforcement.

### 3. Run the ShopLedger Client (Mode A)
Execute transactions directly against the MySQL database:
```bash
# Display product inventory
python lab.py client-cli products

# View low stock report
python lab.py client-cli low-stock

# Generate daily sales report
python lab.py client-cli daily-sales

# Create a new invoice
python lab.py client-cli create-invoice --customer-id 1 --items 3:2,5:1

# Launch the interactive Textual Terminal UI
python lab.py client-ui
```

### 4. Switch Between Architectures
```bash
# Switch to Two-Tier (Mode A)
python lab.py mode-a

# Switch to Three-Tier (Mode B)
python lab.py mode-b

# Inspect active firewall rules and packet counters
python lab.py status
```

### 5. Start the Controller API & Dashboard
```bash
# Start the Controller API daemon on http://127.0.0.1:8080
python lab.py controller

# In another terminal, serve the dashboard:
python -m http.server 8000
# Open http://localhost:8000 in your browser
```

### 6. Run the Empirical Evidence Pipeline
To regenerate all latency benchmarks, Nmap scans, packet dissections, and JSON evidence:
```bash
python evidence/run_all.py
```

### 7. Run Unit Tests
```bash
npm test
# Or: node tests.js
```
Validates the state machine, architecture selector, SVG topology renderer, trade-off cards, and rule engine.

---

## 9. Inspecting Packet Captures in Wireshark

All packet captures are written to [`captures/`](file:///f:/CN-MP/captures):
```bash
# View captured packets using tcpdump inside the container
docker exec lab_sniffer tcpdump -nr /captures/live.pcap0 -c 20
```

### Helpful Wireshark Display Filters
- **Direct MySQL Traffic (Mode A):**
  `tcp.port == 3306 && mysql`
- **TLS Handshake & Encrypted Application Records (Mode B):**
  `tcp.port == 443 && (tls.handshake.type == 1 || tls.record.content_type == 23)`
- **Inter-tier ICMP Diagnostics:**
  `icmp.type == 8 || icmp.type == 0`
- **Firewall Drops (TCP SYN without ACK):**
  `tcp.flags.syn == 1 && tcp.flags.ack == 0`

---

## 10. Repository File Structure

```text
CN-MP/
├── app/                        # Tier 3: FastAPI Application Tier (10.0.2.10:5000)
│   ├── Dockerfile              # Python 3.11 slim image
│   ├── entrypoint.sh           # Waits for MySQL, runs app
│   ├── main.py                 # REST endpoints, parameterized queries with app_user
│   └── requirements.txt        # fastapi, uvicorn, mysql-connector-python
├── captures/                   # Output directory for live .pcap captures (.gitignore protected)
│   └── .gitkeep
├── client/                     # Tier 1: Client Workstation Tier (192.168.1.20)
│   ├── Dockerfile              # Debian image with Python, nmap, netcat, traceroute
│   ├── entrypoint.sh           # Configures default gateway, starts host ingress relay
│   ├── shopledger_cli.py       # Mode A direct MySQL CLI client
│   ├── shopledger_ui.py        # Mode A interactive Textual TUI client
│   └── requirements.txt        # textual, mysql-connector-python, rich
├── controller/                 # Local Controller API (127.0.0.1:8080)
│   ├── main.py                 # FastAPI service bridging UI and Docker lab
│   └── requirements.txt        # fastapi, uvicorn, pydantic
├── db/                         # Tier 4: MySQL 8.0 Database Tier (10.0.3.10:3306)
│   ├── Dockerfile              # Pinned mysql:8.0-debian image
│   ├── entrypoint.sh           # Gateway routing configuration
│   ├── init.sql                # Schema, 3 user roles, 50 products, 20 customers, 100 invoices
│   └── my.cnf                  # Custom MySQL server configuration
├── evidence/                   # Reproducible benchmarks and empirical audit data
│   ├── latency.json            # 100-run empirical latency measurements
│   ├── mode_a_dissection.txt   # Plaintext MySQL protocol wire dissection
│   ├── mode_b_dissection.txt   # TLS 1.3 encrypted protocol wire dissection
│   ├── nmap_mode_a.txt         # Real Nmap port scan output in Mode A
│   ├── nmap_mode_b.txt         # Real Nmap port scan output in Mode B
│   ├── recorded_data.json      # Complete recorded snapshot for Vercel static replay
│   └── run_all.py              # Automated evidence generation and benchmark script
├── firewall/                   # Router & Firewall Tier (Alpine Linux)
│   ├── rules/
│   │   ├── mode-a.sh           # Mode A iptables rules (Client -> DB 3306 ALLOW)
│   │   ├── mode-b.sh           # Mode B iptables rules (Segmented 3-tier ALLOW)
│   │   └── mode-custom.sh      # Custom dynamic ruleset template
│   ├── Dockerfile              # Alpine with iptables, conntrack-tools, python3
│   ├── entrypoint.sh           # Configures interfaces, IP forwarding, launches fw_daemon
│   └── fw_daemon.py            # Token-authenticated Unix socket/mgmt daemon (:9099)
├── sniffer/                    # Multi-Interface Packet Capture Service
│   ├── Dockerfile              # Alpine with tcpdump
│   └── entrypoint.sh           # Parallel per-interface and aggregate rotating packet sniffers
├── web/                        # Tier 2: Web / Reverse Proxy Tier (10.0.1.10:443)
│   ├── html/
│   │   └── index.html          # Lightweight Mode B browser portal
│   ├── Dockerfile              # Nginx alpine with openssl TLS self-signed generation
│   ├── entrypoint.sh           # Gateway configuration and Nginx start
│   └── nginx.conf              # TLS 1.3 config with proxy_pass to app:5000
├── docker-compose.yml          # Lab network definitions & 6 container specifications
├── index.html                  # Network Workbench v2 Dashboard (Vanilla HTML5)
├── lab.py                      # Master cross-platform CLI lab orchestrator
├── Makefile                    # Make command shortcuts
├── package.json                # Project metadata and test scripts
├── README.md                   # Comprehensive project documentation
├── script.js                   # Dashboard logic (Dual live/recorded, SVG topology, charts)
├── style.css                   # Responsive stylesheet with accessibility & themes
└── tests.js                    # Unit tests for dashboard logic and state machine
```

---

## 11. Academic Integrity & Citations

- **Curriculum:** Computer Networks (CN) Mini-Project.
- **Architectural Reference:** Silberschatz, Korth, Sudarshan — *Database System Concepts* (Multi-tier architectures).
- **Network Security Reference:** Cheswick, Bellovin, Rubin — *Firewalls and Internet Security: Repelling the Wily Hacker*.
- **Standard Protocol References:** RFC 8446 (The Transport Layer Security (TLS) Protocol Version 1.3), RFC 793 (Transmission Control Protocol), RFC 792 (Internet Control Message Protocol).
- **License:** [MIT License](file:///f:/CN-MP/LICENSE)
