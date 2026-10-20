# Network Workbench v2 — Real Two-Tier vs Three-Tier Network Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose_v2-2496ED?logo=docker&logoColor=white)](file:///f:/CN-MP/docker-compose.yml)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](file:///f:/CN-MP/controller/main.py)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?logo=mysql&logoColor=white)](file:///f:/CN-MP/db/init.sql)
[![Nginx](https://img.shields.io/badge/Nginx-TLS_1.3-009639?logo=nginx&logoColor=white)](file:///f:/CN-MP/web/nginx.conf)
[![Tests Passing](https://img.shields.io/badge/Tests-100%25_Passing-success)](file:///f:/CN-MP/tests.js)

**Network Workbench v2** turns a browser simulator into a fully operational, empirical Computer Networks laboratory. It deploys an authentic inventory and billing application (**ShopLedger**) across isolated Docker subnets governed by a stateful Linux kernel `iptables` firewall router, complete with packet sniffing (`.pcap`), real Nmap audits, Wireshark dissections, and dual Live/Recorded web dashboards.

---

## ⚡ 3-Command Quick Start

Make sure Docker is running, then copy the environment template and start the lab:

```bash
# 1. Copy environment configuration
cp .env.example .env

# 2. Build and launch all 6 container tiers on isolated subnets
python lab.py start

# 3. Verify cross-tier firewall isolation in both modes (14 tests)
python lab.py verify
```

*(On Windows without `cp`, run `copy .env.example .env` in PowerShell or cmd).*

---

## 🖥️ The 3 User Interfaces of Network Workbench v2

| Interface | Type | How to Open & What It Does |
| :--- | :--- | :--- |
| **Network Workbench Dashboard** | Graphical Web Page | Run `python -m http.server 8000`, then open `http://localhost:8000` in your browser. Features dynamic SVG topology, Mode A/B/Custom architecture switch, Evidence tab, pure-SVG latency comparison charts, Nmap scan tabs, packet dissections, and guided syllabus lessons. |
| **ShopLedger Web App (Mode B)** | Graphical Web Page | Open `https://127.0.0.1:8443` in your browser (click through self-signed certificate warning). Served by Nginx TLS 1.3 reverse proxy through the client ingress relay crossing the firewall to FastAPI and MySQL. |
| **ShopLedger Client (Mode A)** | Terminal TUI | Run `python lab.py client-ui`. Interactive text-based terminal UI drawn directly in your terminal with menus, searchable product catalog, real-time stock levels, and direct MySQL transactions. |

---

## 🧭 Project Architecture at a Glance

```
MODE A: Two-Tier (Client-Server LAN)
  lab_client (192.168.1.20) === TCP 3306 (MySQL) ===> lab_firewall ===> lab_db (10.0.3.10:3306)

MODE B: Three-Tier (Segmented DMZ)
  lab_client (192.168.1.20) === TLS 443 ===> lab_web (10.0.1.10) === HTTP 5000 ===> lab_app (10.0.2.10) === MySQL 3306 ===> lab_db
```

| Subnet | CIDR Block | Container | Role & Software |
| :--- | :--- | :--- | :--- |
| `client_net` | `192.168.1.0/24` | `lab_client` (`192.168.1.20`) | Python CLI/Textual TUI Workstation + Host Relay (`:8443`) |
| `web_net` | `10.0.1.0/24` | `lab_web` (`10.0.1.10`) | Nginx TLS 1.3 Reverse Proxy (`:443`) |
| `app_net` | `10.0.2.0/24` | `lab_app` (`10.0.2.10`) | FastAPI Application Logic Service (`:5000`) |
| `db_net` | `10.0.3.0/24` | `lab_db` (`10.0.3.10`) | MySQL Community Server 8.0 (`:3306`) |
| `mgmt_net` | `172.28.0.0/24` | `lab_firewall` (`172.28.0.254`) | Alpine Router, Stateful iptables, Token Daemon (`:9099`) |

*All application networks are designated `internal: true`, forcing all inter-tier transit through `lab_firewall`.*

---

## 🛠️ Essential Command Reference

All operations are automated via cross-platform [`lab.py`](file:///f:/CN-MP/lab.py) (and [`Makefile`](file:///f:/CN-MP/Makefile)):

```bash
# Architecture Switching
python lab.py mode-a         # Switch firewall to Mode A (Two-Tier direct client->DB)
python lab.py mode-b         # Switch firewall to Mode B (Three-Tier segmented DMZ)
python lab.py status         # Show container health and kernel iptables rule counters

# ShopLedger Client (Mode A)
python lab.py client-cli products       # List inventory from MySQL via client_user
python lab.py client-cli daily-sales    # Run daily sales aggregation report
python lab.py client-ui                 # Launch interactive Textual terminal UI

# Security & Performance Demos
python lab.py tls-demo       # Compare Mode A unencrypted vs TLS 1.3 required
python lab.py tamper-demo    # Show client SQL price tamper vs Mode B API rejection
python evidence/run_all.py   # Run 100-iteration benchmarks and generate evidence

# Local Controller & Dashboard
python lab.py controller     # Start FastAPI Controller API on http://127.0.0.1:8080
python -m http.server 8000   # Serve dashboard at http://localhost:8000
npm test                     # Run automated test suite (100% passing)
```

---

## 📊 Key Empirical Findings

1. **Latency Profile:**
   - **Persistent Connection Reuse:** Two-Tier is **$21.9\times$ faster** ($\text{Median} = 0.21\,\text{ms}$ vs $4.59\,\text{ms}$).
   - **Per-Request Connection Setup:** Two-Tier is **$7.7\times$ faster** ($\text{Median} = 1.14\,\text{ms}$ vs $8.72\,\text{ms}$).
2. **Security Trade-Off:**
   - **Two-Tier (Mode A):** High speed, but credentials live on client and SQL privileges cannot prevent domain price tampering.
   - **Three-Tier (Mode B):** $+4.4\,\text{ms}$ protocol overhead, but database is fully isolated and centralized API middleware rejects tampering with HTTP 400.
3. **Transport Encryption:** Plaintext on port 3306 is a **configuration choice**, not an inherent flaw of Two-Tier. Two-tier networks can enforce TLS 1.3 encryption directly over MySQL sockets.

---

## 📚 Complete Documentation Index

- [**`docs/DEMO_SCRIPT.md`**](file:///f:/CN-MP/docs/DEMO_SCRIPT.md): **5-Minute Live Presentation Script** for teachers/examiners.
- [**`docs/VIVA.md`**](file:///f:/CN-MP/docs/VIVA.md): **25 Viva Q&As** (Docker firewalls, latency attribution, real-world apps).
- [**`docs/architecture.md`**](file:///f:/CN-MP/docs/architecture.md): Deep dive into Two-Tier vs Three-Tier design and subnet routing.
- [**`docs/benchmarks.md`**](file:///f:/CN-MP/docs/benchmarks.md): Benchmark methodology, warm-up drops, and limitations note.
- [**`docs/security-audit.md`**](file:///f:/CN-MP/docs/security-audit.md): Least privilege SQL grants, secrets scan findings, and tamper analysis.
- [**`docs/firewall-rules.md`**](file:///f:/CN-MP/docs/firewall-rules.md): Stateful filtering, `conntrack`, and per-mode iptables scripts.
- [**`docs/wireshark-recipes.md`**](file:///f:/CN-MP/docs/wireshark-recipes.md): Packet captures guide and Wireshark display filters.
