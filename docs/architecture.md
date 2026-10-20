# Network Architecture: Two-Tier vs Three-Tier

## 1. Overview & Context

Traditional educational simulators often model network topologies as a single immutable chain:
$$\text{Client} \longrightarrow \text{Web Server} \longrightarrow \text{Application Server} \longrightarrow \text{Database Server}$$

While this three-tier model represents modern public web applications, real enterprise networks deploy multiple valid architectural patterns based on specific organizational boundaries, trust models, and performance constraints.

Network Workbench v2 models and implements two distinct architectural paradigms running the exact same business inventory and billing software (**ShopLedger**) over isolated Linux network namespaces.

---

## 2. Architecture Comparison

### Mode A: Two-Tier Client-Server Architecture

In Mode A, thick desktop clients connect directly to the database service on port `3306`:

```
+------------------------------------+
|   Desktop Workstation / Terminal   |
|   lab_client (192.168.1.20)        |
+------------------------------------+
                  │  TCP Port 3306 (Binary MySQL Wire Protocol)
                  ▼
+------------------------------------+
|   Linux Router / Stateful Firewall |
|   lab_firewall (192.168.1.254)     |
+------------------------------------+
                  │  Forwarded via db_net (10.0.3.0/24)
                  ▼
+------------------------------------+
|   Central Relational Database      |
|   lab_db (10.0.3.10:3306)          |
+------------------------------------+
```

#### Production Examples:
- **TallyPrime / Tally.ERP 9:** Accounting terminals in an enterprise LAN querying a central Tally Server or SQL database host over local sockets.
- **Retail & Supermarket POS Terminals:** Dedicated checkout lanes executing direct atomic transactions against an on-premise relational database.
- **Hospital Information Systems (HIS):** Clinical nurse stations and radiology workstations (e.g. Epic Hyperspace thick client) talking directly to an enterprise database cluster.
- **Bloomberg Professional Terminal & SAP GUI:** High-frequency desktop client workstations maintaining direct data sessions.

---

### Mode B: Three-Tier Multi-Hop Architecture

In Mode B, client access to internal subnets is blocked at the perimeter. All client requests terminate at a reverse proxy and transit through an intermediate application tier:

```
+------------------------------------+
|   Browser / External Client        |
|   lab_client (192.168.1.20)        |
+------------------------------------+
                  │  TLS 1.3 / HTTPS (Port 443)
                  ▼
+------------------------------------+
|   DMZ Reverse Proxy (Nginx)        |
|   lab_web (10.0.1.10:443)          |
+------------------------------------+
                  │  Internal HTTP (Port 5000)
                  ▼
+------------------------------------+
|   Business Logic API (FastAPI)     |
|   lab_app (10.0.2.10:5000)         |
+------------------------------------+
                  │  SQL Connection Pool (Port 3306)
                  ▼
+------------------------------------+
|   Central Relational Database      |
|   lab_db (10.0.3.10:3306)          |
+------------------------------------+
```

#### Production Examples:
- **Public E-Commerce Portals:** Amazon, Shopify (anonymous external shoppers connecting over TLS).
- **Online Banking & Fintech Platforms:** Zero-trust perimeters with strict database isolation.
- **Multi-Tenant SaaS Applications:** Centralized REST APIs abstracting physical storage schemas.

---

## 3. Subnet Addressing & Isolation

All application networks are configured with `internal: true` in [`docker-compose.yml`](file:///f:/CN-MP/docker-compose.yml). This prevents Docker's default bridge gateway from routing inter-tier traffic and forces all packets to traverse the central router container (`lab_firewall`).

| Subnet Name | CIDR Block | Container Name | Interface IP | Gateway IP | Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `client_net` | `192.168.1.0/24` | `lab_client` | `192.168.1.20` | `192.168.1.254` | Client Workstation & Relay |
| `web_net` | `10.0.1.0/24` | `lab_web` | `10.0.1.10` | `10.0.1.254` | Nginx TLS 1.3 Reverse Proxy |
| `app_net` | `10.0.2.0/24` | `lab_app` | `10.0.2.10` | `10.0.2.254` | FastAPI Application Logic |
| `db_net` | `10.0.3.0/24` | `lab_db` | `10.0.3.10` | `10.0.3.254` | MySQL 8.0 Database Engine |
| `mgmt_net` | `172.28.0.0/24` | `lab_firewall` | `172.28.0.254` | `172.28.0.1` | Isolated Controller Daemon |

---

## 4. Host Ingress Architecture

To enable a standard web browser on the host machine (e.g. Windows) to interact with Mode B's Nginx portal (`10.0.1.10:443`) while strictly preserving packet traversal across the firewall:
1. `lab_client` exposes a local relay port on `127.0.0.1:8443`.
2. Traffic sent from the host browser to `https://127.0.0.1:8443` enters `lab_client`'s network namespace.
3. The relay forwards traffic to `10.0.1.10:443` via default route `192.168.1.254` (`lab_firewall`).
4. In Mode B, the firewall permits the packet.
5. In Mode A, the firewall drops the packet and the host browser times out.
