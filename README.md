# Computer Networks Mini-Project: Secure 3-Tier Web Application

A full-stack, secure three-tier application demonstrating production network isolation, firewall policy enforcement, and role-based access control, integrated with an interactive educational network simulator.

---

## 🏛️ Architecture Overview

The system implements the classic **Secure Three-Tier Architecture** modeled in computer network engineering:

```
[ Client Browser ]
  (192.168.1.20)
        │
        │ HTTP / HTTPS (TCP :80 / :443)
        ▼
┌───────────────────────────────────────────┐
│ Tier 1: Web Tier (Nginx Reverse Proxy)    │  [cn_public_net] & [cn_app_net]
│ - Handles public client ingress           │
│ - Injects security & anti-sniff headers   │
│ - Proxies `/api/` traffic to Flask        │
└───────────────────────────────────────────┘
        │
        │ Internal TCP :5000
        ▼
┌───────────────────────────────────────────┐
│ Tier 2: Application Tier (Python Flask)   │  [cn_app_net] & [cn_db_net]
│ - Enforces Authentication & Session State │
│ - Role-Based Access Control (Admin/User)  │
│ - Sanitizes queries & audits packet flow  │
└───────────────────────────────────────────┘
        │
        │ Internal TCP :3306
        ▼
┌───────────────────────────────────────────┐
│ Tier 3: Database Tier (MySQL 8.0)         │  [cn_db_net] (ISOLATED)
│ - Stores student & academic records       │
│ - Zero public or host port exposure       │
│ - Accessible ONLY by Application Tier     │
└───────────────────────────────────────────┘
```

---

## 🔒 Network Security & Isolation Enforcements

1. **Subnet Segmentation with Docker Networks**:
   - `cn_public_net`: Connects external clients and Nginx.
   - `cn_app_net`: Connects Nginx and Flask backend.
   - `cn_db_net` (`internal: true`): Isolated backend network for Flask and MySQL only. No external gateway or public routing.
2. **Blocked Direct Access**:
   - The MySQL database container does **not** map port 3306 to the host.
   - Direct requests from clients or the Web Tier to MySQL port 3306 are dropped by firewall and network policy.
3. **Least Privilege Principle**:
   - The Application server authenticates to MySQL via a restricted service account (`flask_app`) granting only necessary CRUD operations on the `student_portal` database.
4. **Live Network Audit Logging**:
   - Every cross-tier transit, query execution, and authorization check is recorded in the `network_audit_logs` table.

---

## 🚀 Running the Project

### Option A: With Docker (Recommended for Containerized Isolation)

Ensure Docker Desktop / Docker Engine is running:

```sh
docker compose up -d --build
```

- Open [http://localhost](http://localhost) in your browser.
- To shut down:
  ```sh
  docker compose down
  ```

### Option B: Standalone Local Runner (Immediate / No Docker Required)

A built-in Python runner starts the Application Tier and serves the frontend on port 5000 with automatic fallback to an identical local database:

```sh
python run_local.py --open
```

Or double-click `run-local.bat` on Windows.

- Open [http://localhost:5000#portal](http://localhost:5000#portal) in your browser.

---

## 🔑 Pre-Configured Demo Credentials

| Role | Username | Password | Capabilities |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `Admin@123` | Full CRUD on student records, view network security audit logs |
| **Student** | `student` | `Student@123` | View student directory, view individual academic profiles |
| **Faculty** | `faculty` | `Faculty@123` | View directory & academic standing |
| **Guest** | *(default)* | *(none)* | Read-only access; prompted to log in for administrative changes |

---

## 🧪 Interactive Features & Simulator

1. **Student Portal (Live 3-Tier App)** (`#portal`):
   - **Student Directory**: Search by name or roll number, filter by academic department or enrollment status.
   - **Student Management (Admin)**: Create, edit, and delete student records with instant DB persistence.
   - **Academic Profile**: Inspect detailed course enrollments, letter grades, GPA, and attendance percentages.
   - **Real-Time 3-Tier Packet Inspector**: Visualizes live HTTP/TCP packet journeys through Tier 1 (Nginx), Tier 2 (Flask), and Tier 3 (MySQL).
   - **Boundary Penetration Test**: One-click simulation of an attacker attempting to bypass Web/App tiers directly into MySQL port 3306, demonstrating firewall block decisions.
2. **Network Workbench Simulator** (`#overview`, `#simulate`, `#rules`, `#learn`):
   - Interactive packet builder with customizable source, destination, protocol, and port.
   - Centralized firewall policy table with editable ALLOW/DENY rules and reset capabilities.
   - Guided educational lessons and knowledge checks on IP addressing, port semantics, and TCP vs UDP transport.

---

## 🛠️ Verification & Test Suite

Run the built-in regression test suite:

```sh
node tests-v4.js
```

Covers:
- Firewall baseline validation and rule mutation safeguards
- Transport state machine and packet loss reconstruction
- Educational interactive lesson checkpoints and quiz scoring
