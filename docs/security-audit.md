# Security Audit, Secret Management & Tamper Analysis

## 1. Secrets Scan Findings & Environment Management

### Scan Methodology
A dedicated scanning script ([`scripts/secrets_scan.py`](file:///f:/CN-MP/scripts/secrets_scan.py)) audits all source files in the working directory and parses every commit diff in the entire Git history for passwords, API keys, tokens, and private keys.

### Audit Findings
- **Git Commit History:** Clean. No production API keys, AWS credentials, or SSH private keys have ever been committed.
- **Database Backup Verification:** Verified that `history.db` was **never** committed to Git in any commit in the repository history. Both `.gitignore` and `package.json` protect against SQLite and cache commits.
- **Credential Centralization:** All database passwords (`MYSQL_ROOT_PASSWORD`, `MYSQL_APP_PASSWORD`, `MYSQL_CLIENT_PASSWORD`), controller tokens (`LAB_CONTROLLER_TOKEN`), and firewall tokens (`FW_TOKEN`) reside exclusively in `.env` (gitignored), with a clean template provided in [`.env.example`](file:///f:/CN-MP/.env.example).

---

## 2. Controller API Hardening

The Controller service ([`controller/main.py`](file:///f:/CN-MP/controller/main.py)) implements defense-in-depth controls:

### 1. Host-Header Allowlist (DNS Rebinding Mitigation)
To prevent cross-site request forgery and DNS rebinding attacks where an external domain name resolves to `127.0.0.1`, a strict Starlette middleware validates incoming `Host` headers against an explicit allowlist:
```python
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "localhost:8080", "127.0.0.1:8080"}
```
Any request presenting an external Host header is terminated immediately with `400 Bad Request`.

### 2. Token Authentication for Mutating Endpoints
Mutating operations that alter the state of the network lab (`POST /mode`, `POST /rules/custom`) require a valid `X-Lab-Token` header:
- Unauthenticated or invalid requests return `401 Unauthorized`.
- Non-mutating read endpoints (`GET /status`, `GET /rules`, `GET /captures`, `POST /probe`) remain readable by local dashboards.

---

## 3. How `/status` and `/probe` Reach the Containers

To avoid exposing Docker sockets or application containers to the host network:
1. **`/status` Telemetry:**
   - Container operational state is retrieved via `docker ps --filter name=lab_`.
   - Active firewall rules and packet counters are queried over the isolated management network (`mgmt_net`, interface `172.28.0.254:9099`) with shared bearer token authentication (`X-FW-Token`).
   - Tenant tiers (`client_net`, `web_net`, `app_net`, `db_net`) are physically forbidden from reaching `:9099` by the firewall router's `INPUT` chain default-drop policy.

2. **`/probe` Execution:**
   - The Controller does **not** originate probe packets from the host.
   - It issues `docker exec` to the specified source container (e.g. `lab_client`) using explicit argument vectors (preventing shell injection).
   - The probe command (`nc -zv` or `ping`) generates genuine network frames inside the source container's namespace.
   - The packet transits virtual interfaces across the router (`lab_firewall`), where iptables `FORWARD` rules enforce the policy.
   - The Controller observes latency and verifies which firewall rule matched.

---

## 4. Stock Decrement & Price Tampering Demonstration

### The Architectural Dilemma: Authorization vs Domain Business Logic
In Two-Tier (Mode A), the desktop client connects directly to MySQL with `client_user`.
`client_user` is provisioned under the principle of least privilege in [`db/init.sql`](file:///f:/CN-MP/db/init.sql):
```sql
GRANT SELECT ON shopledger.products TO 'client_user'@'%';
GRANT UPDATE (stock) ON shopledger.products TO 'client_user'@'%';
GRANT SELECT ON shopledger.customers TO 'client_user'@'%';
GRANT SELECT, INSERT ON shopledger.invoices TO 'client_user'@'%';
GRANT SELECT, INSERT ON shopledger.invoice_items TO 'client_user'@'%';
```

**How Stock is Decremented:**
When an invoice is issued, the client executes:
```sql
UPDATE products SET stock = stock - 1 WHERE id = 2;
```
The database allows this because `client_user` has `GRANT UPDATE (stock) ON shopledger.products`.

### The Vulnerability: Client-Side Price Tampering
Because authorization in Two-Tier occurs **solely at the SQL privilege layer**, the database has no awareness of domain-level pricing invariants. A modified or compromised client can execute:
```sql
INSERT INTO invoice_items (invoice_id, product_id, quantity, unit_price, line_total)
VALUES (101, 2, 1, 0.01, 0.01);
```
The database commits the transaction without error. The customer purchases a **$499.50 monitor for $0.01**.

### How Mode B (Three-Tier) Solves This
In Mode B, the client connects to FastAPI. The client cannot send SQL statements; it sends an abstract purchase intent:
```json
{
  "customer_id": 1,
  "items": [{ "product_sku": "SKU-1002", "quantity": 1 }]
}
```
If an attacker attempts to inject a fraudulent `unit_price: 0.01`, the FastAPI middleware queries the trusted product catalog, detects the discrepancy, rolls back the transaction, and returns:
```json
HTTP 400 Bad Request
{
  "detail": "Price manipulation rejected: Client submitted unit_price $0.01 does not match catalog price $499.50 for SKU 'SKU-1002'."
}
```
This is verifiable via `python lab.py tamper-demo`.
