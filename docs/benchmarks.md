# Empirical Latency Benchmarks & Performance Analysis

## 1. Methodology & Experimental Rigor

To provide a fair, authentic, and scientific comparison between Two-Tier (Mode A) and Three-Tier (Mode B), the benchmark suite in [`evidence/run_all.py`](file:///f:/CN-MP/evidence/run_all.py) implements the following testing methodology:

1. **Warm-Up Runs Dropped:** The first 5 iterations in each benchmark run are discarded to eliminate JIT compilation, cold TCP socket setup, and DNS/ARP resolution anomalies.
2. **Standard Sample Size:** 100 consecutive iterations are recorded per test variant.
3. **Identical Business Operations:** Both modes execute the exact same query (`SELECT id, sku, price, stock FROM products LIMIT 5`).
4. **Dual Connection Profiles:** Evaluated under two distinct network connection models:
   - **Persistent Connection Reuse:** Evaluating steady-state application performance with pre-established connections.
   - **Per-Request Connection Establishment:** Evaluating cold-start and unpooled public request performance.

---

## 2. Benchmark Results (100 Iterations, Warm-Up Dropped)

### Scenario A: Persistent Connection Reuse

In this scenario:
- **Mode A:** Client maintains an open, stateful TCP connection to MySQL (`10.0.3.10:3306`), issuing binary queries in a loop.
- **Mode B:** Client maintains an open HTTP/1.1 Keep-Alive session to Nginx (`10.0.1.10:443`), issuing HTTPS requests in a loop.

| Metric | Mode A: Two-Tier (Direct MySQL) | Mode B: Three-Tier (Nginx $\to$ App $\to$ DB) | Absolute Overhead | Speedup Factor |
| :--- | :--- | :--- | :--- | :--- |
| **Minimum** | $0.20\,\text{ms}$ | $4.07\,\text{ms}$ | $+3.87\,\text{ms}$ | **$20.4\times$ faster** |
| **Median (P50)** | **$0.21\,\text{ms}$** | **$4.59\,\text{ms}$** | **$+4.38\,\text{ms}$** | **$21.9\times$ faster** |
| **Mean** | $0.23\,\text{ms}$ | $4.68\,\text{ms}$ | $+4.45\,\text{ms}$ | **$20.4\times$ faster** |
| **95th Percentile (P95)** | **$0.29\,\text{ms}$** | **$5.67\,\text{ms}$** | **$+5.38\,\text{ms}$** | **$19.6\times$ faster** |
| **99th Percentile (P99)** | $0.41\,\text{ms}$ | $6.03\,\text{ms}$ | $+5.62\,\text{ms}$ | **$14.7\times$ faster** |
| **Standard Deviation** | $0.05\,\text{ms}$ | $0.41\,\text{ms}$ | — | — |

---

### Scenario B: Per-Request Connection Establishment

In this scenario:
- **Mode A:** Client establishes a brand-new TCP socket and completes the MySQL authentication handshake on every query, then closes the socket.
- **Mode B:** Client establishes a brand-new TCP socket, completes a full TLS 1.3 handshake with Nginx, sends the HTTP request, receives the JSON response, and closes the socket.

| Metric | Mode A: Two-Tier (New MySQL Conn) | Mode B: Three-Tier (New TLS Conn) | Absolute Overhead | Speedup Factor |
| :--- | :--- | :--- | :--- | :--- |
| **Minimum** | $0.94\,\text{ms}$ | $7.87\,\text{ms}$ | $+6.93\,\text{ms}$ | **$8.4\times$ faster** |
| **Median (P50)** | **$1.14\,\text{ms}$** | **$8.72\,\text{ms}$** | **$+7.58\,\text{ms}$** | **$7.7\times$ faster** |
| **Mean** | $1.21\,\text{ms}$ | $8.86\,\text{ms}$ | $+7.65\,\text{ms}$ | **$7.3\times$ faster** |
| **95th Percentile (P95)** | **$1.50\,\text{ms}$** | **$9.33\,\text{ms}$** | **$+7.83\,\text{ms}$** | **$6.2\times$ faster** |
| **99th Percentile (P99)** | $2.02\,\text{ms}$ | $9.80\,\text{ms}$ | $+7.78\,\text{ms}$ | **$4.9\times$ faster** |
| **Standard Deviation** | $0.22\,\text{ms}$ | $0.47\,\text{ms}$ | — | — |

---

## 3. Overhead Attribution Analysis

Why does Mode B require $+4.4\,\text{ms}$ (steady-state) to $+7.6\,\text{ms}$ (connection setup)?

1. **Hop Count:** Mode A traverses 1 virtual router hop (Client $\leftrightarrow$ Router $\leftrightarrow$ DB). Mode B traverses 3 virtual router hops (Client $\leftrightarrow$ Web $\leftrightarrow$ App $\leftrightarrow$ DB).
2. **Crypto & Protocol Negotiation:** In per-request mode, TLS 1.3 key exchange (ECDHE key generation, certificate exchange, symmetric AES-GCM cipher setup) incurs significant CPU and latency costs before the first application byte is transmitted.
3. **Application Stack & Serialization:** Mode A decodes compact binary MySQL rows directly into native memory buffers. Mode B undergoes Nginx reverse-proxy socket dispatch, Python ASGI request parsing in FastAPI, Pydantic schema validation, internal MySQL query execution, JSON string serialization, and HTTP payload transfer.

---

## 4. Benchmark Limitations & Nuances

When evaluating these measurements, several real-world engineering constraints must be recognized:

1. **Local Host Bridge Environment:** All containers run within a single physical host machine. Real-world WAN propagation delay (typically 15–120 ms across cities/continents) and ISP routing jitter are absent.
2. **Payload Size:** The benchmark query fetches 5 product rows (~400 bytes). For large batch queries (e.g. 50,000 rows), database serialization and disk I/O dominate over network protocol overhead.
3. **Serialized Concurrency:** The benchmark executes sequentially ($c = 1$). In high-concurrency production environments ($c > 500$ simultaneous clients), Two-Tier Mode A degrades rapidly due to MySQL connection limits (`max_connections = 151` default), whereas Mode B handles high concurrency gracefully by multiplexing client requests through application-tier connection pools.
