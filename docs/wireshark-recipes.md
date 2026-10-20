# Wireshark Inspection Recipes & Packet Analysis

## 1. Capture Artifacts

The packet sniffer container (`lab_sniffer`) attaches directly to the firewall router's network namespace (`network_mode: "service:firewall"`). It records native Ethernet captures across each interface:

| Capture File | Monitored Subnet / Interface | Description |
| :--- | :--- | :--- |
| `live.pcap0` | All interfaces (`-i any`) | Complete aggregate multi-tier timeline. |
| `client.pcap0` | `client_net` (`eth1`) | Ingress packets from the client workstation (`192.168.1.20`). |
| `web.pcap0` | `web_net` (`eth2`) | DMZ traffic reaching Nginx reverse proxy (`10.0.1.10:443`). |
| `app.pcap0` | `app_net` (`eth3`) | Internal API calls between Nginx and FastAPI (`10.0.2.10:5000`). |
| `db.pcap0` | `db_net` (`eth4`) | Database queries reaching MySQL Server (`10.0.3.10:3306`). |

Sample captures are committed to [`evidence/samples/`](file:///f:/CN-MP/evidence/samples) for offline and recorded replay.

---

## 2. Essential Wireshark Display Filters

### 1. Two-Tier MySQL Protocol Inspection (Mode A)
Filter for direct database transactions originating from the client workstation:
```wireshark
ip.src == 192.168.1.20 && tcp.port == 3306
```
- **Inspect Handshake:** Expand `MySQL Protocol -> Handshake Initialization Packet`.
- **Inspect Plaintext Queries:** Expand `MySQL Protocol -> Command: COM_QUERY`. Observe readable SQL text (`SELECT id, sku...`).

### 2. Transport Security Verification (TLS vs Plaintext)
Compare unencrypted Two-Tier traffic against TLS-encrypted traffic:
- **Plaintext MySQL:**
  ```wireshark
  tcp.port == 3306 && mysql.query
  ```
- **Encrypted MySQL (TLS Mode A):**
  ```wireshark
  tcp.port == 3306 && tls.handshake.type == 1
  ```
  Observe `Client Hello` on port `3306` followed by `TLS_AES_256_GCM_SHA384` encrypted records.

### 3. Three-Tier Multi-Hop Trace (Mode B)
Filter for the full three-tier progression of a single request:
```wireshark
(tcp.port == 443) || (tcp.port == 5000) || (tcp.port == 3306)
```
1. **Packet 1–3:** TCP 3-way handshake on port 443 (`192.168.1.20 -> 10.0.1.10`).
2. **Packet 4–8:** TLS 1.3 handshake negotiation.
3. **Packet 9–11:** TCP 3-way handshake on port 5000 (`10.0.1.10 -> 10.0.2.10`).
4. **Packet 12:** FastAPI executes SQL query over internal connection (`10.0.2.10 -> 10.0.3.10:3306`).

### 4. Detecting Firewall Drops
Filter for TCP connection attempts that received no ACK due to firewall DROP:
```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0
```
In Mode B, packets from `192.168.1.20` to `10.0.3.10:3306` appear with multiple TCP retransmissions and no response, confirming default-drop policy enforcement.
