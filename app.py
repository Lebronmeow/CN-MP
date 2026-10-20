"""
Network Workbench 2.0 — Backend Service
Network Troubleshooting and Firewall Policy Analyzer for Small Networks

Provides:
1. Real DNS resolution and TCP connection probing via Python standard socket.
2. Static firewall policy analysis engine (detects broad rules, shadows, conflicts, ordering).
3. SQLite database for test and audit history.
4. Built-in controllable demo server for classroom/lab demonstrations.
5. Downloadable and printable diagnostic reports.
6. Static file serving for the Network Workbench web interface.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from flask import Flask, jsonify, request, send_from_directory, Response

# Base directory for static assets and database
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "history.db")

app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")


# ============================================================================
# Database Initialization & Helpers
# ============================================================================

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS connectivity_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            status TEXT NOT NULL,
            latency_ms REAL,
            dns_latency_ms REAL,
            resolved_ips TEXT,
            canonical_name TEXT,
            error_code TEXT,
            message TEXT,
            explanation TEXT,
            is_safe INTEGER DEFAULT 1
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS policy_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            policy_name TEXT NOT NULL,
            rule_count INTEGER NOT NULL,
            critical_count INTEGER NOT NULL,
            warning_count INTEGER NOT NULL,
            info_count INTEGER NOT NULL,
            findings_json TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# ============================================================================
# Safety Guard for Diagnostic Probes
# ============================================================================

def check_target_safety(target: str, allow_public: bool = False) -> Tuple[bool, str, str]:
    """
    Validates target destination. Restricts real checks to localhost,
    private lab subnets (RFC 1918), or explicitly authorized targets.
    Returns: (is_safe, category, reason)
    """
    target = target.strip()
    if not target:
        return False, "INVALID", "Target host or IP cannot be empty."

    # Strip port if user pasted host:port into host field
    if ":" in target and not target.startswith("[") and not target.count(":") > 1:
        parts = target.split(":")
        target = parts[0]

    # Check for direct localhost aliases
    if target.lower() in ("localhost", "127.0.0.1", "::1", "localhost.localdomain"):
        return True, "LOCALHOST", "Target is local loopback (authorized for safe local testing)."

    # Check if target is an IP address
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_loopback:
            return True, "LOCALHOST", "Target is local loopback interface."
        if ip.is_private:
            return True, "PRIVATE_LAB", f"Target belongs to private subnet ({ip}). Safe for lab diagnostics."
        if ip.is_reserved or ip.is_link_local:
            return True, "PRIVATE_LAB", "Target is link-local or reserved address."
        
        # Public IP
        if allow_public:
            return True, "PUBLIC_AUTHORIZED", f"Public IP ({ip}) explicitly authorized by user."
        return False, "PUBLIC_RESTRICTED", (
            f"Target {ip} is a public Internet IP. For security and responsible diagnostic testing, "
            "external scans require explicit authorization. Enable 'Allow Authorized Public Targets' to proceed."
        )
    except ValueError:
        # It's a hostname / FQDN
        pass

    # Common safe diagnostic targets
    SAFE_PUBLIC_DOMAINS = {
        "example.com", "example.org", "example.net",
        "one.one.one.one", "dns.google", "scanme.nmap.org"
    }

    if target.lower() in SAFE_PUBLIC_DOMAINS:
        return True, "SAFE_PUBLIC", f"Target {target} is a recognized public testing domain."

    if allow_public:
        return True, "PUBLIC_AUTHORIZED", f"Public hostname ({target}) explicitly authorized by user."

    return False, "PUBLIC_RESTRICTED", (
        f"'{target}' appears to be a public hostname. To prevent unauthorized outbound probing, "
        "Network Workbench limits tests to localhost and private lab networks by default. "
        "Check 'Allow Authorized Public Targets' if you have permission to test this host."
    )


# ============================================================================
# Network Diagnostics Engine (DNS & TCP Probes)
# ============================================================================

def resolve_dns(host: str) -> Dict[str, Any]:
    """
    Performs genuine DNS resolution using Python standard socket.
    Measures resolution latency in milliseconds and retrieves all mapped IPs.
    """
    start_time = time.perf_counter()
    clean_host = host.strip()
    if ":" in clean_host and not clean_host.count(":") > 1:
        clean_host = clean_host.split(":")[0]

    try:
        # socket.getaddrinfo handles both IPv4 and IPv6
        addr_infos = socket.getaddrinfo(clean_host, None)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        
        ips = sorted(list({info[4][0] for info in addr_infos}))
        canonical = clean_host
        try:
            name, _, _ = socket.gethostbyname_ex(clean_host)
            canonical = name
        except Exception:
            pass

        return {
            "success": True,
            "latency_ms": elapsed_ms,
            "ips": ips,
            "canonical_name": canonical,
            "error": None
        }
    except socket.gaierror as e:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "success": False,
            "latency_ms": elapsed_ms,
            "ips": [],
            "canonical_name": None,
            "error": f"DNS Resolution Error: {e.strerror} (Code {e.errno})"
        }
    except Exception as e:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "success": False,
            "latency_ms": elapsed_ms,
            "ips": [],
            "canonical_name": None,
            "error": f"DNS Lookup Exception: {str(e)}"
        }


def probe_tcp_connection(target_ip: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Performs real TCP 3-way handshake attempt.
    Differentiates between:
    - OPEN / REACHABLE (SYN-ACK received)
    - REFUSED / UNREACHABLE (RST packet returned -> host alive, service closed)
    - TIMED_OUT / FILTERED (no reply -> packet dropped by firewall or dead route)
    - HOST_UNREACHABLE / ROUTE_ERROR
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start_time = time.perf_counter()

    try:
        sock.connect((target_ip, port))
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        sock.close()
        return {
            "status": "REACHABLE",
            "state_label": "Reachable (Port Open)",
            "code": "OPEN",
            "latency_ms": elapsed_ms,
            "message": f"TCP connection successfully established to {target_ip}:{port} in {elapsed_ms}ms.",
            "explanation": (
                "The 3-way handshake completed (SYN -> SYN/ACK -> ACK). The host is active, "
                "the network route is operational, and an application service is listening on this port."
            )
        }
    except socket.timeout:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        sock.close()
        return {
            "status": "TIMED_OUT",
            "state_label": "Timed Out (Filtered / Dropped)",
            "code": "TIMEOUT",
            "latency_ms": elapsed_ms,
            "message": f"TCP connection attempt to {target_ip}:{port} timed out after {timeout} seconds.",
            "explanation": (
                "No response packet was received (neither SYN/ACK nor RST). In computer networking, "
                "this typically indicates an active firewall dropping packets silently (DROP policy) "
                "or an unrouted destination."
            )
        }
    except ConnectionRefusedError:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        sock.close()
        return {
            "status": "UNREACHABLE",
            "state_label": "Connection Refused (RST)",
            "code": "REFUSED",
            "latency_ms": elapsed_ms,
            "message": f"Connection refused by {target_ip}:{port} (TCP RST returned).",
            "explanation": (
                "The target host is online and network connectivity is intact, but the operating system "
                f"actively sent a TCP Reset (RST) packet. Crucial distinction: A firewall did NOT block this; "
                f"the target service or server process is simply stopped or not listening on port {port}."
            )
        }
    except OSError as e:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        sock.close()
        err_str = str(e)
        code = "NETWORK_ERROR"
        if "10061" in err_str:
            return {
                "status": "UNREACHABLE",
                "state_label": "Connection Refused (WSAECONNREFUSED)",
                "code": "REFUSED",
                "latency_ms": elapsed_ms,
                "message": f"Connection refused by {target_ip}:{port}.",
                "explanation": (
                    "The target host is reachable, but returned a reset. The service is stopped or not listening. "
                    "This is not a firewall block."
                )
            }
        return {
            "status": "UNREACHABLE",
            "state_label": "Network / Host Unreachable",
            "code": code,
            "latency_ms": elapsed_ms,
            "message": f"Socket connection failed: {err_str}",
            "explanation": (
                "Operating system returned an error during socket creation/connection. "
                "Check network adapter, gateway, or routing table."
            )
        }


# ============================================================================
# Firewall Policy Analyzer Engine
# ============================================================================

SENSITIVE_PORTS = {
    21: "FTP (Plaintext credentials)",
    22: "SSH (Remote Management)",
    23: "Telnet (Insecure Plaintext Management)",
    25: "SMTP (Mail relay / Spam risk)",
    80: "HTTP (Unencrypted Web)",
    110: "POP3 (Insecure Mail)",
    135: "RPC Endpoint Mapper (Windows Exploits)",
    139: "NetBIOS (SMB File Sharing)",
    445: "SMB (File Sharing / Ransomware target)",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop Protocol)",
    5432: "PostgreSQL Database",
    5900: "VNC Remote Desktop",
    6379: "Redis (In-memory cache/NoSQL)",
    9200: "Elasticsearch",
    27017: "MongoDB Database"
}


def parse_port_range(port_str: Any) -> Tuple[int, int]:
    """Parses port or range string like '80', '8080-8088', '*' into (min, max)."""
    p = str(port_str).strip()
    if p in ("*", "ANY", "any", ""):
        return 1, 65535
    if "-" in p:
        parts = p.split("-")
        try:
            return int(parts[0]), int(parts[1])
        except ValueError:
            return 1, 65535
    try:
        val = int(p)
        return val, val
    except ValueError:
        return 1, 65535


def parse_ip_network(ip_str: str) -> Optional[ipaddress.IPv4Network]:
    """Helper to convert subnet/IP string to IPv4Network object."""
    s = ip_str.strip()
    if s in ("ANY", "any", "*", "0.0.0.0/0", "0.0.0.0"):
        return ipaddress.IPv4Network("0.0.0.0/0")
    if s.lower() == "client":
        return ipaddress.IPv4Network("192.168.1.0/24")
    if s.lower() == "web":
        return ipaddress.IPv4Network("10.0.1.0/24")
    if s.lower() == "app":
        return ipaddress.IPv4Network("10.0.2.0/24")
    if s.lower() == "database":
        return ipaddress.IPv4Network("10.0.3.0/24")
    try:
        if "/" in s:
            return ipaddress.IPv4Network(s, strict=False)
        return ipaddress.IPv4Network(f"{s}/32", strict=False)
    except ValueError:
        return None


def is_network_subnet_of(net_a: Optional[ipaddress.IPv4Network], net_b: Optional[ipaddress.IPv4Network]) -> bool:
    """Returns True if net_a is a subnet of net_b (net_a is more specific or equal)."""
    if net_a is None or net_b is None:
        return False
    return net_a.subnet_of(net_b)


class PolicyAnalyzer:
    """
    Audits a firewall policy rule set for:
    1. Overly broad access & sensitive port exposure
    2. Shadowed and redundant rules
    3. Contradictory / conflicting rules
    4. Rule-order hazards (early default-deny)
    5. Three-tier architecture direct bypasses
    6. Missing explicit default-deny rule
    """

    def __init__(self, rules: List[Dict[str, Any]]):
        self.raw_rules = rules
        self.findings: List[Dict[str, Any]] = []

    def analyze(self) -> Dict[str, Any]:
        self.findings = []
        rules = self.raw_rules

        if not rules:
            self.findings.append({
                "rule_id": "GLOBAL",
                "severity": "CRITICAL",
                "category": "EMPTY_POLICY",
                "title": "Empty Firewall Policy",
                "description": "No firewall rules were supplied to analyze.",
                "remediation": "Define explicit ingress and egress policies conforming to least-privilege principles."
            })
            return self._build_report()

        # Step 1: Analyze individual rules for broadness and sensitive exposure
        has_default_deny = False
        default_deny_index = -1

        for idx, rule in enumerate(rules):
            r_id = rule.get("id") or f"R-{idx+1:02d}"
            src = str(rule.get("source", "")).strip()
            dst = str(rule.get("destination", "")).strip()
            proto = str(rule.get("protocol", "TCP")).upper().strip()
            port_str = str(rule.get("port", "")).strip()
            action = str(rule.get("action") or rule.get("decision", "DENY")).upper().strip()
            p_min, p_max = parse_port_range(port_str)

            is_src_any = src in ("ANY", "any", "*", "0.0.0.0/0", "0.0.0.0")
            is_dst_any = dst in ("ANY", "any", "*", "0.0.0.0/0", "0.0.0.0")
            is_port_any = (p_min == 1 and p_max == 65535)

            # Check for Default Deny
            if is_src_any and is_dst_any and is_port_any and action in ("DENY", "DROP", "REJECT"):
                has_default_deny = True
                default_deny_index = idx

            # Check Overly Broad Allow
            if action in ("ALLOW", "ACCEPT", "PERMIT"):
                if is_src_any and is_dst_any and is_port_any:
                    self.findings.append({
                        "rule_id": r_id,
                        "rule_index": idx,
                        "severity": "CRITICAL",
                        "category": "UNRESTRICTED_ALLOW",
                        "title": "Permissive ANY-ANY Allow Rule",
                        "description": (
                            f"Rule {r_id} permits all traffic from ANY source to ANY destination on ALL ports. "
                            "This renders all subsequent perimeter defenses ineffective."
                        ),
                        "remediation": "Restrict source to authorized subnets and specify explicit required service ports."
                    })
                elif is_src_any and is_port_any:
                    self.findings.append({
                        "rule_id": r_id,
                        "rule_index": idx,
                        "severity": "HIGH",
                        "category": "WILDCARD_PORT_ALLOW",
                        "title": f"Unrestricted Port Range to {dst}",
                        "description": (
                            f"Rule {r_id} allows ANY source to reach destination '{dst}' across all 65,535 ports."
                        ),
                        "remediation": "Limit the rule to strictly required destination ports (e.g. 443 for HTTPS)."
                    })

                # Check Sensitive Port Exposure to WAN / ANY
                if is_src_any or src == "192.168.1.0/24" or src.lower() == "client":
                    for sport, sname in SENSITIVE_PORTS.items():
                        if p_min <= sport <= p_max:
                            sev = "CRITICAL" if sport in (22, 23, 3389, 3306, 5432, 27017, 6379, 445) else "WARNING"
                            self.findings.append({
                                "rule_id": r_id,
                                "rule_index": idx,
                                "severity": sev,
                                "category": "SENSITIVE_PORT_EXPOSURE",
                                "title": f"Sensitive Service Exposed: Port {sport} ({sname})",
                                "description": (
                                    f"Rule {r_id} permits untrusted/WAN source '{src}' to access {sname} (port {sport}) "
                                    f"on destination '{dst}'."
                                ),
                                "remediation": (
                                    f"Bind {sname} exclusively to private management subnets (e.g. 10.0.x.x) or "
                                    "require access through a secure VPN bastion. Never expose directly to untrusted networks."
                                )
                            })

            # Check Three-Tier Architecture Violations
            # If Client connects directly to Database
            src_lower = src.lower()
            dst_lower = dst.lower()
            if (src_lower in ("client", "192.168.1.20", "192.168.1.0/24") or "192.168." in src_lower) and \
               (dst_lower in ("database", "10.0.3.10", "10.0.3.0/24") or p_min <= 3306 <= p_max) and \
               action in ("ALLOW", "ACCEPT"):
                self.findings.append({
                    "rule_id": r_id,
                    "rule_index": idx,
                    "severity": "HIGH",
                    "category": "TIER_BYPASS",
                    "title": "Three-Tier Architecture Direct Database Bypass",
                    "description": (
                        f"Rule {r_id} grants direct client access to the private database tier. "
                        "In a secure three-tier design, clients must only communicate with the public Web tier, "
                        "and the database tier must only accept connections from the Application tier."
                    ),
                    "remediation": "Revoke direct client-to-database access. Query data exclusively through the application API tier."
                })

            # If Web connects directly to Database bypassing App
            if (src_lower in ("web", "10.0.1.10", "10.0.1.0/24")) and \
               (dst_lower in ("database", "10.0.3.10", "10.0.3.0/24") or p_min <= 3306 <= p_max) and \
               action in ("ALLOW", "ACCEPT"):
                self.findings.append({
                    "rule_id": r_id,
                    "rule_index": idx,
                    "severity": "HIGH",
                    "category": "TIER_BYPASS",
                    "title": "Web Tier Direct Database Access",
                    "description": (
                        f"Rule {r_id} allows the Web tier to directly access the database, bypassing application logic."
                    ),
                    "remediation": "Route data requests through the application server (10.0.2.10) to enforce validation and business rules."
                })

        # Step 2: Analyze Multi-rule Relationships (Shadowing, Conflicts, Order Hazards)
        for i in range(len(rules)):
            r_a = rules[i]
            id_a = r_a.get("id") or f"R-{i+1:02d}"
            act_a = str(r_a.get("action") or r_a.get("decision", "DENY")).upper().strip()
            src_a_net = parse_ip_network(str(r_a.get("source", "")))
            dst_a_net = parse_ip_network(str(r_a.get("destination", "")))
            p_a_min, p_a_max = parse_port_range(r_a.get("port", ""))
            proto_a = str(r_a.get("protocol", "TCP")).upper().strip()

            for j in range(i + 1, len(rules)):
                r_b = rules[j]
                id_b = r_b.get("id") or f"R-{j+1:02d}"
                act_b = str(r_b.get("action") or r_b.get("decision", "DENY")).upper().strip()
                src_b_net = parse_ip_network(str(r_b.get("source", "")))
                dst_b_net = parse_ip_network(str(r_b.get("destination", "")))
                p_b_min, p_b_max = parse_port_range(r_b.get("port", ""))
                proto_b = str(r_b.get("protocol", "TCP")).upper().strip()

                # Protocol compatibility
                proto_match = (proto_a == "ANY" or proto_b == "ANY" or proto_a == proto_b)

                # Does Rule A subsume Rule B?
                # (Rule A source encompasses Rule B source, Dest A encompasses Dest B, Port A encompasses Port B)
                src_subsumed = is_network_subnet_of(src_b_net, src_a_net)
                dst_subsumed = is_network_subnet_of(dst_b_net, dst_a_net)
                port_subsumed = (p_a_min <= p_b_min and p_a_max >= p_b_max)

                if proto_match and src_subsumed and dst_subsumed and port_subsumed:
                    if act_a == act_b:
                        # Redundant / duplicate rule
                        self.findings.append({
                            "rule_id": id_b,
                            "rule_index": j,
                            "related_rule_id": id_a,
                            "severity": "INFO",
                            "category": "REDUNDANT_RULE",
                            "title": f"Redundant Rule ({id_b} shadowed by {id_a})",
                            "description": (
                                f"Rule {id_b} ({act_b}) is completely covered by earlier rule {id_a} ({act_a}). "
                                f"All traffic matching {id_b} is already handled by {id_a} with the identical action."
                            ),
                            "remediation": f"Safely remove rule {id_b} to optimize policy table evaluation."
                        })
                    else:
                        # Conflicting / Shadowed rule (Different actions!)
                        self.findings.append({
                            "rule_id": id_b,
                            "rule_index": j,
                            "related_rule_id": id_a,
                            "severity": "CRITICAL" if act_b == "DENY" else "HIGH",
                            "category": "SHADOWED_RULE",
                            "title": f"Shadowed Rule Conflict ({id_b} hidden by {id_a})",
                            "description": (
                                f"Rule {id_b} specifies action '{act_b}', but earlier rule {id_a} specifies '{act_a}' "
                                f"for a broader or identical scope. Because firewalls evaluate rules in first-match order, "
                                f"rule {id_b} will NEVER be executed (dead policy)."
                            ),
                            "remediation": (
                                f"Rule Order Correction: Move specific rule {id_b} ABOVE broader rule {id_a} "
                                "so specific exceptions take precedence."
                            )
                        })

        # Step 3: Check Rule-Order Hazard for Default Deny
        if has_default_deny and default_deny_index < len(rules) - 1:
            dead_rules_count = len(rules) - 1 - default_deny_index
            r_deny_id = rules[default_deny_index].get("id") or f"R-{default_deny_index+1:02d}"
            self.findings.append({
                "rule_id": r_deny_id,
                "rule_index": default_deny_index,
                "severity": "CRITICAL",
                "category": "ORDER_HAZARD",
                "title": "Early Default-Deny Hazard",
                "description": (
                    f"A catch-all DENY rule ({r_deny_id}) is positioned at index {default_deny_index+1}. "
                    f"There are {dead_rules_count} rules placed AFTER it. Every rule following this catch-all "
                    "is completely unreachable because firewalls stop evaluation on the first match."
                ),
                "remediation": "Relocate the catch-all Default-Deny rule to the very end of the policy chain."
            })

        # Step 4: Missing Default Deny check
        if not has_default_deny:
            self.findings.append({
                "rule_id": "GLOBAL",
                "severity": "WARNING",
                "category": "MISSING_DEFAULT_DENY",
                "title": "Missing Explicit Default-Deny Baseline",
                "description": (
                    "The policy does not terminate with an explicit 'DENY ALL' rule. If the underlying firewall "
                    "implementation falls back to an implicit permit (allow-by-default), unmatched traffic will bypass controls."
                ),
                "remediation": "Append an explicit rule at the bottom of the table: ANY -> ANY : ANY -> DENY."
            })

        return self._build_report()

    def _build_report(self) -> Dict[str, Any]:
        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        warning = sum(1 for f in self.findings if f["severity"] in ("HIGH", "WARNING"))
        info = sum(1 for f in self.findings if f["severity"] == "INFO")

        return {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "rule_count": len(self.raw_rules),
            "summary": {
                "critical": critical,
                "warning": warning,
                "info": info,
                "total_findings": len(self.findings)
            },
            "findings": self.findings,
            "disclaimer": (
                "Notice: These findings are derived from static firewall rule policy analysis, "
                "not proof that a real firewall is vulnerable. Findings identify logic ambiguities, "
                "least-privilege violations, and rule-ordering hazards."
            )
        }


# ============================================================================
# Built-in Controllable Demo Server
# ============================================================================

class DemoHttpHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({
            "service": "Network Workbench 2.0 Test Web Service",
            "status": "RUNNING",
            "port": self.server.server_port,
            "time": datetime.now(timezone.utc).isoformat()
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Suppress noisy standard request logging
        pass


class DemoServerController:
    """Manages a background HTTP test server on port 8080 for easy demonstrations."""
    def __init__(self, port: int = 8080):
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()

    def is_running(self) -> bool:
        return self.server is not None

    def start(self) -> Tuple[bool, str]:
        with self.lock:
            if self.server is not None:
                return True, f"Demo server already active on port {self.port}"
            try:
                self.server = HTTPServer(("127.0.0.1", self.port), DemoHttpHandler)
                self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
                self.thread.start()
                return True, f"Demo server successfully started on 127.0.0.1:{self.port}"
            except OSError as e:
                self.server = None
                return False, f"Could not bind port {self.port}: {str(e)}"

    def stop(self) -> Tuple[bool, str]:
        with self.lock:
            if self.server is None:
                return True, "Demo server is not currently running"
            try:
                self.server.shutdown()
                self.server.server_close()
                self.server = None
                self.thread = None
                return True, f"Demo server on port {self.port} stopped (port closed)"
            except Exception as e:
                self.server = None
                return False, f"Error stopping demo server: {str(e)}"


demo_controller = DemoServerController(port=8080)


# ============================================================================
# API Routes
# ============================================================================

@app.route("/api/status", methods=["GET"])
def get_status():
    return jsonify({
        "status": "ONLINE",
        "service": "Network Workbench 2.0 Backend",
        "python_version": sys.version,
        "demo_server": {
            "running": demo_controller.is_running(),
            "port": demo_controller.port
        },
        "database": os.path.exists(DB_PATH),
        "disclaimer": "Diagnostic tools are designed for authorized lab education and network testing."
    })


@app.route("/api/diagnostics/run", methods=["POST"])
def run_diagnostics():
    data = request.get_json(force=True, silent=True) or {}
    host = str(data.get("host", "127.0.0.1")).strip()
    port = int(data.get("port", 80))
    timeout = float(data.get("timeout", 3.0))
    allow_public = bool(data.get("allow_public", False))

    if port < 1 or port > 65535:
        return jsonify({"error": "Port must be an integer between 1 and 65535"}), 400

    # Safety Guard Evaluation
    is_safe, category, safety_reason = check_target_safety(host, allow_public=allow_public)
    if not is_safe:
        return jsonify({
            "success": False,
            "blocked_by_safety": True,
            "category": category,
            "error": safety_reason,
            "host": host,
            "port": port
        }), 403

    # Step 1: DNS Resolution
    dns_res = resolve_dns(host)

    # Step 2: TCP Connection Attempt
    # If DNS succeeded, probe first resolved IP; else probe raw target
    probe_ip = dns_res["ips"][0] if (dns_res["success"] and dns_res["ips"]) else host
    tcp_res = probe_tcp_connection(probe_ip, port, timeout=timeout)

    # Combined results
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "target": {
            "host": host,
            "port": port,
            "category": category,
            "probe_ip": probe_ip
        },
        "dns": dns_res,
        "tcp": tcp_res,
        "summary": {
            "status": tcp_res["status"],
            "state_label": tcp_res["state_label"],
            "overall_reachable": (tcp_res["status"] == "REACHABLE"),
            "dns_resolved": dns_res["success"],
            "total_latency_ms": round(dns_res["latency_ms"] + tcp_res["latency_ms"], 2)
        },
        "limitations": [
            "DNS resolution verifies domain mapping, but does not guarantee the IP route is functional.",
            "A TCP connection check proves port state (Open vs Closed vs Filtered), but does not inspect higher-level TLS or HTTP authentication.",
            "Connection Refused (RST) proves network packets reached the host and were rejected by the OS, meaning the service is down, NOT that a firewall blocked it."
        ]
    }

    # Save to SQLite Database
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO connectivity_tests (
                timestamp, host, port, status, latency_ms, dns_latency_ms,
                resolved_ips, canonical_name, error_code, message, explanation, is_safe
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result["timestamp"],
            host,
            port,
            tcp_res["status"],
            tcp_res["latency_ms"],
            dns_res["latency_ms"],
            json.dumps(dns_res["ips"]),
            dns_res.get("canonical_name", ""),
            tcp_res.get("code", ""),
            tcp_res.get("message", ""),
            tcp_res.get("explanation", ""),
            1 if is_safe else 0
        ))
        conn.commit()
        result["test_id"] = cur.lastrowid
        conn.close()
    except Exception as db_err:
        result["db_warning"] = f"Failed to record in history database: {str(db_err)}"

    return jsonify(result)


@app.route("/api/analyzer/run", methods=["POST"])
def run_analyzer():
    data = request.get_json(force=True, silent=True) or {}
    rules = data.get("rules", [])
    policy_name = data.get("name", "Custom Policy")

    analyzer = PolicyAnalyzer(rules)
    report = analyzer.analyze()
    report["policy_name"] = policy_name

    # Save to SQLite database
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO policy_audits (
                timestamp, policy_name, rule_count, critical_count,
                warning_count, info_count, findings_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            report["timestamp"],
            policy_name,
            report["rule_count"],
            report["summary"]["critical"],
            report["summary"]["warning"],
            report["summary"]["info"],
            json.dumps(report["findings"])
        ))
        conn.commit()
        report["audit_id"] = cur.lastrowid
        conn.close()
    except Exception as db_err:
        report["db_warning"] = f"Failed to record audit in database: {str(db_err)}"

    return jsonify(report)


@app.route("/api/demo-server/toggle", methods=["POST"])
def toggle_demo_server():
    data = request.get_json(force=True, silent=True) or {}
    action = data.get("action", "toggle")

    if action == "start":
        success, msg = demo_controller.start()
    elif action == "stop":
        success, msg = demo_controller.stop()
    else:
        if demo_controller.is_running():
            success, msg = demo_controller.stop()
        else:
            success, msg = demo_controller.start()

    return jsonify({
        "success": success,
        "message": msg,
        "running": demo_controller.is_running(),
        "port": demo_controller.port
    })


@app.route("/api/history", methods=["GET"])
def get_history():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM connectivity_tests
        ORDER BY id DESC LIMIT 50
    """)
    tests = [dict(row) for row in cur.fetchall()]

    cur.execute("""
        SELECT * FROM policy_audits
        ORDER BY id DESC LIMIT 20
    """)
    audits = [dict(row) for row in cur.fetchall()]
    conn.close()

    # Parse JSON fields
    for t in tests:
        if t.get("resolved_ips"):
            try:
                t["resolved_ips"] = json.loads(t["resolved_ips"])
            except Exception:
                pass
    for a in audits:
        if a.get("findings_json"):
            try:
                a["findings"] = json.loads(a["findings_json"])
            except Exception:
                a["findings"] = []

    return jsonify({
        "tests": tests,
        "audits": audits
    })


@app.route("/api/history/clear", methods=["POST"])
def clear_history():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM connectivity_tests")
    cur.execute("DELETE FROM policy_audits")
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "History cleared successfully."})


# ============================================================================
# Frontend Static Asset Serving
# ============================================================================

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/<path:path>")
def static_files(path):
    if os.path.exists(os.path.join(BASE_DIR, path)):
        return send_from_directory(BASE_DIR, path)
    return send_from_directory(BASE_DIR, "index.html")


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Workbench 2.0 Server")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind (default: 5000)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--demo-server", action="store_true", help="Automatically start test server on port 8080")
    args = parser.parse_args()

    init_db()

    if args.demo_server:
        demo_controller.start()
        print(f"[DEMO SERVER] Started automatically on http://127.0.0.1:8080")

    print(f"============================================================")
    print(f"Network Workbench 2.0 — Starting Server")
    print(f"Web Interface: http://{args.host}:{args.port}/")
    print(f"API Diagnostics: http://{args.host}:{args.port}/api/diagnostics/run")
    print(f"Policy Analyzer: http://{args.host}:{args.port}/api/analyzer/run")
    print(f"Demo Server:     http://127.0.0.1:8080 (Start/Stop via UI or API)")
    print(f"============================================================")

    app.run(host=args.host, port=args.port, debug=False)
