# Network Workbench 2.0
### Network Troubleshooting and Firewall Policy Analyzer for Small Networks

Network Workbench 2.0 combines an interactive three-tier network simulator with genuine DNS resolution, live TCP socket connectivity testing, automated firewall policy analysis, and printable diagnostic assessment reports.

---

## 1. What the Application Does

### A. Real Network Diagnostics
- Probes real hostnames and service ports (e.g., `127.0.0.1:8080`, `127.0.0.1:3306`, `example.com:443`).
- Performs real DNS resolution (resolving IP lists, canonical names, and timing latency).
- Executes real TCP 3-way handshakes using Python standard sockets.
- Differentiates between:
  - **Reachable / Open** (`SYN-ACK` received).
  - **Connection Refused** (`TCP RST` returned &mdash; host is active, but service daemon is stopped; **not** a firewall drop!).
  - **Timed Out / Filtered** (Packets silently dropped by a firewall or unrouted).
- Built-in safety guard restricts tests to localhost and RFC 1918 private subnets by default, with an authorization toggle for external testing.

### B. Firewall Policy Analyzer
- Audits rule logic for:
  - **Overly broad rules:** `0.0.0.0/0` or wildcard ports allowing sensitive management/database ports (`22` SSH, `3306` MySQL, `3389` RDP).
  - **Shadowed rules:** Preceding broad rules rendering subsequent specific rules dead code.
  - **Conflicting rules:** Inconsistent ALLOW vs. DENY actions for the same traffic.
  - **Rule-order hazards:** Early Default-Deny rules placed before specific exceptions.
  - **Three-tier architecture bypasses:** Direct client-to-database or web-to-database access.
  - **Missing default deny:** Warns if policy does not terminate with an explicit `DENY ALL`.

### C. Three-Tier Simulator & Troubleshooting Correlation
- Preserves the visual three-tier educational packet simulation (Client, Web, App, Database).
- **Troubleshooting Comparison Mode:** Compares theoretical firewall decisions against real network socket behavior side-by-side.

### D. Assessment Reports & SQLite History
- SQLite database (`history.db`) automatically logs diagnostic checks and policy audits.
- Downloadable and printable diagnostic reports (HTML and Print-to-PDF ready) containing test results, detected flaws, root causes, and administrator recommendations.

---

## 2. Teacher Demonstration Guide

### Demo 1: Proving Real Diagnostics vs. Stopped Service (RST vs. Firewall Drop)
1. Launch the application:
   ```sh
   python app.py
   ```
   Open `http://127.0.0.1:5000/` in your browser.
2. In the **Diagnostics** tab, click **Start Demo Server on :8080**.
3. Run diagnostics on `127.0.0.1:8080`:
   - Result: **REACHABLE (Port Open)**, latency < 5ms.
4. Click **Stop Demo Server**.
5. Run the diagnostic check on `127.0.0.1:8080` again:
   - Result: **CONNECTION REFUSED (TCP RST)**.
   - *Key Networking Insight to Explain to Teacher:* A failed connection alone does not mean a firewall blocked it. Because a TCP RST was returned by the OS, the network path is open, but the service is stopped! If a firewall had dropped the packet, it would have timed out.

### Demo 2: Client Accessing Database Directly (Teacher's Scenario)
1. **In Simulate:**
   - Click the orange **"Teacher Demo: Direct Client &rarr; DB Access"** button.
   - Rule `R-03` (`Client -> Database :3306`) is set to `ALLOW`.
   - The packet travels directly from the client (`192.168.1.20`) to the database (`10.0.3.10:3306`).
   - The trace explains why this is a severe security risk: direct database access bypasses the Application tier logic and validation.
2. **In Policy Analyzer:**
   - Select the preset: **"Teacher Demo: Client Directly Accessing Database (Hazard)"**.
   - Click **Analyze Firewall Policy**.
   - The analyzer flags `R-03` with two critical issues:
     - `[CRITICAL] Sensitive Service Exposed: Port 3306 (MySQL Database)`.
     - `[HIGH] Three-Tier Architecture Direct Database Bypass`.
   - Shows the exact remediation: enforce least privilege by setting rule `R-03` to `DENY` and routing queries through the application tier.
3. **In Troubleshoot:**
   - Select `Client -> Database Server (:3306)` to view the side-by-side correlation matrix.

### Demo 3: Exporting Assessment Report
- Navigate to **Reports**, click **Generate Assessment Report**, and show the printable/downloadable summary containing test findings, root causes, and next steps.

---

## 3. Technology Stack

- **Backend:** Python standard library (`socket`, `sqlite3`, `ipaddress`) + Flask
- **Frontend:** HTML5, CSS3 (Warm editorial paper typography), Vanilla ES6 JavaScript
- **Database:** SQLite (`history.db`)
- **Testing:** Node.js (`tests-v4.js`) and Python `unittest` (`test_backend.py`)

---

## 4. Running the Tests

To verify both the simulation engine and the real-socket backend:

```sh
# Frontend simulation & logic regression tests:
node tests-v4.js

# Backend socket probes, safety filters, and policy analyzer tests:
python test_backend.py
```
