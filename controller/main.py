#!/usr/bin/env python3
"""
Network Workbench v2 — Controller API
Bridge service between the live Docker network lab and the Workbench Dashboard.

Endpoints:
- GET  /status        Current mode, container health, active ruleset summary
- GET  /rules         Parsed iptables rules with per-rule packet & byte counters
- POST /mode          Switch architecture mode ("A", "B", "custom")
- POST /rules/custom  Apply strictly validated custom firewall ruleset
- POST /probe         Execute a live probe from a tier container and record latency & matched rule
- GET  /captures      List pcap files in the captures directory
- GET  /captures/{name} Download a specific pcap file
"""

import json
import os
import re
import shutil
import subprocess
import time
from typing import List, Optional, Union

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPTURES_DIR = os.path.join(BASE_DIR, "captures")
FW_TOKEN = os.environ.get("FW_TOKEN", "lab_firewall_secret_token_2026")

app = FastAPI(
    title="Network Workbench v2 Controller API",
    description="Bridge API between the Network Workbench UI and the isolated multi-tier Docker lab.",
    version="2.0.0"
)

# CORS restricted to local origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://127.0.0.1",
        "http://localhost:3000",
        "http://localhost:5000",
        "http://localhost:8000",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5000",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8080",
        "null",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Strict allowlists for validation
ALLOWED_CONTAINERS = {
    "client": "lab_client",
    "web": "lab_web",
    "app": "lab_app",
    "db": "lab_db",
    "firewall": "lab_firewall",
    "sniffer": "lab_sniffer",
    "192.168.1.20": "lab_client",
    "10.0.1.10": "lab_web",
    "10.0.2.10": "lab_app",
    "10.0.3.10": "lab_db",
    "lab_client": "lab_client",
    "lab_web": "lab_web",
    "lab_app": "lab_app",
    "lab_db": "lab_db",
}

VALID_IPS = {
    "192.168.1.20", "192.168.1.254", "192.168.1.0/24",
    "10.0.1.10", "10.0.1.254", "10.0.1.0/24",
    "10.0.2.10", "10.0.2.254", "10.0.2.0/24",
    "10.0.3.10", "10.0.3.254", "10.0.3.0/24",
    "0.0.0.0/0", "any"
}

VALID_PORTS = {22, 53, 80, 443, 3306, 5000, 8080, 8443, 9099}
VALID_ACTIONS = {"ACCEPT", "DROP", "REJECT"}
VALID_PROTOS = {"tcp", "udp", "icmp", "all"}


def get_docker_cmd():
    """Detect docker executable (either native or via WSL)."""
    if shutil.which("docker"):
        return ["docker"]
    elif shutil.which("wsl"):
        return ["wsl", "-d", "Ubuntu", "-e", "docker"]
    else:
        raise RuntimeError("Neither docker nor wsl found in PATH.")


def exec_container(container_name: str, cmd_list: List[str], timeout: int = 5) -> subprocess.CompletedProcess:
    """Execute a command list in a container without shell interpolation."""
    base_docker = get_docker_cmd()
    full_cmd = base_docker + ["exec", container_name] + cmd_list
    return subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)


def query_fw_daemon(method: str, path: str, payload: Optional[dict] = None) -> dict:
    """Query the fw_daemon running inside lab_firewall via authenticated exec."""
    curl_args = [
        "curl", "-s", "-m", "3", "--noproxy", "*",
        "-H", f"X-FW-Token: {FW_TOKEN}",
        "-H", "Content-Type: application/json",
        "-X", method,
    ]
    if payload is not None:
        curl_args += ["-d", json.dumps(payload)]
    curl_args.append(f"http://172.28.0.254:9099{path}")

    res = exec_container("lab_firewall", curl_args, timeout=5)
    if res.returncode != 0:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Firewall daemon query failed: {res.stderr.strip()}"
        )
    try:
        return json.loads(res.stdout.strip())
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Invalid response from fw_daemon: {res.stdout.strip()} ({e})"
        )


def get_container_statuses() -> dict:
    """Fetch status for all lab containers."""
    base_docker = get_docker_cmd()
    try:
        cmd = base_docker + [
            "ps", "-a",
            "--filter", "name=lab_",
            "--format", "{{.Names}}\t{{.Status}}\t{{.State}}"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        statuses = {}
        for line in res.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                statuses[parts[0]] = {
                    "status": parts[1],
                    "state": parts[2],
                    "running": (parts[2].lower() == "running")
                }
        return statuses
    except Exception as e:
        return {"error": str(e)}


# -------------------------------------------------------------
# Request / Response Models
# -------------------------------------------------------------
class ModeRequest(BaseModel):
    mode: str = Field(..., description="Architecture mode: 'A' (Two-Tier), 'B' (Three-Tier), or 'custom'")


class RuleItem(BaseModel):
    source: str = Field(..., description="Source IP or CIDR (e.g., 192.168.1.20)")
    destination: str = Field(..., description="Destination IP or CIDR (e.g., 10.0.3.10)")
    port: Optional[Union[int, str]] = Field(None, description="Target port number (e.g., 3306) or None")
    proto: str = Field("tcp", description="Protocol: 'tcp', 'udp', or 'icmp'")
    action: str = Field("ACCEPT", description="Action: 'ACCEPT', 'DROP', or 'REJECT'")


class CustomRulesRequest(BaseModel):
    rules: List[RuleItem]


class ProbeRequest(BaseModel):
    src: str = Field("client", description="Source container: 'client', 'web', 'app', 'db'")
    dst: str = Field(..., description="Destination IP address (e.g., 10.0.3.10)")
    port: Optional[Union[int, str]] = Field(None, description="Destination port (e.g., 3306)")
    proto: str = Field("tcp", description="Protocol: 'tcp', 'udp', 'icmp'")


# -------------------------------------------------------------
# Endpoints
# -------------------------------------------------------------
@app.get("/health")
def health_check():
    return {"status": "ok", "service": "Network Workbench v2 Controller"}


@app.get("/status")
def get_status():
    """Returns current architecture mode, container health, and rule counts."""
    fw_status = query_fw_daemon("GET", "/status")
    containers = get_container_statuses()

    mode = fw_status.get("mode", "unknown")
    mode_descriptions = {
        "A": "Two-Tier Architecture (Client -> MySQL Direct Access)",
        "B": "Three-Tier Architecture (Client -> Nginx TLS -> FastAPI -> MySQL)",
        "custom": "Custom User-Defined Ruleset"
    }

    return {
        "mode": mode,
        "description": mode_descriptions.get(mode, "Custom Configuration"),
        "rules_count": fw_status.get("rules_count", 0),
        "containers": containers,
        "ip_forward": fw_status.get("ip_forward", 1)
    }


@app.get("/rules")
def get_rules():
    """Returns parsed iptables rules with per-rule packet and byte counters, plus raw iptables -S lines."""
    fw_rules = query_fw_daemon("GET", "/rules")

    # Fetch raw iptables -S FORWARD lines
    raw_res = exec_container("lab_firewall", ["iptables", "-S", "FORWARD"], timeout=5)
    raw_lines = [l.strip() for l in raw_res.stdout.splitlines() if l.strip()]

    return {
        "mode": fw_rules.get("mode", "unknown"),
        "rules": fw_rules.get("rules", []),
        "raw_rules": raw_lines
    }


@app.post("/mode")
def set_mode(req: ModeRequest):
    """Switch architecture mode ('A', 'B', 'custom') without data loss."""
    mode_upper = req.mode.upper() if req.mode.lower() in {"a", "b"} else req.mode.lower()
    if mode_upper not in {"A", "B", "custom"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mode must be 'A' (Two-Tier), 'B' (Three-Tier), or 'custom'."
        )

    result = query_fw_daemon("POST", "/mode", {"mode": mode_upper})
    return result


@app.post("/rules/custom")
def set_custom_rules(req: CustomRulesRequest):
    """Apply a validated custom ruleset without shell interpolation."""
    payload_rules = []
    for r in req.rules:
        src = r.source.strip()
        dst = r.destination.strip()
        proto = r.proto.strip().lower()
        action = r.action.strip().upper()

        if src not in VALID_IPS or dst not in VALID_IPS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid IP address: {src} -> {dst}. Must be within lab subnet specifications."
            )
        if action not in VALID_ACTIONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid action: {action}. Must be ACCEPT, DROP, or REJECT."
            )
        if proto not in VALID_PROTOS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid protocol: {proto}. Must be tcp, udp, or icmp."
            )

        port_val = None
        if r.port is not None and str(r.port).strip() not in {"", "any", "0"}:
            try:
                p = int(r.port)
                if p not in VALID_PORTS and not (1 <= p <= 65535):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Port {p} out of allowable range."
                    )
                port_val = p
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid port value: {r.port}"
                )

        payload_rules.append({
            "source": src,
            "destination": dst,
            "port": port_val,
            "proto": proto,
            "action": action
        })

    result = query_fw_daemon("POST", "/rules/custom", {"rules": payload_rules})
    return result


@app.post("/probe")
def run_probe(req: ProbeRequest):
    """
    Execute a real probe FROM the specified container to dst:port.
    Measures latency in milliseconds and identifies which firewall rule matched.
    """
    src_key = req.src.lower().strip()
    if src_key not in ALLOWED_CONTAINERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown source container: {req.src}. Allowed: {list(ALLOWED_CONTAINERS.keys())}"
        )
    container_name = ALLOWED_CONTAINERS[src_key]

    dst_ip = req.dst.strip()
    if dst_ip not in VALID_IPS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid destination IP: {dst_ip}"
        )

    proto = req.proto.lower().strip()
    port = req.port
    if proto not in {"tcp", "udp", "icmp"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsupported protocol: {proto}")

    if proto in {"tcp", "udp"} and (port is None or str(port).strip() == ""):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Port is required for TCP/UDP probes")

    # Fetch rule counters before probe
    rules_before = query_fw_daemon("GET", "/rules").get("rules", [])

    t0 = time.perf_counter()
    probe_status = "unknown"
    cmd_output = ""

    try:
        if proto == "icmp":
            res = exec_container(container_name, ["ping", "-c", "1", "-W", "1", dst_ip], timeout=3)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            cmd_output = res.stdout + res.stderr
            if res.returncode == 0 and ("0% loss" in cmd_output or "0% packet loss" in cmd_output):
                probe_status = "open"
                # Parse ping RTT if available
                m = re.search(r"time=([0-9.]+)\s*ms", cmd_output)
                if m:
                    elapsed_ms = float(m.group(1))
            else:
                probe_status = "filtered"

        elif proto == "tcp":
            port_num = int(port)
            if container_name == "lab_db":
                # MySQL container lacks nc, use python or bash socket test
                check_script = (
                    f"import socket, sys; "
                    f"s = socket.socket(); s.settimeout(1.0); "
                    f"sys.exit(0 if s.connect_ex(('{dst_ip}', {port_num})) == 0 else 1)"
                )
                res = exec_container(container_name, ["python3", "-c", check_script], timeout=3)
            else:
                res = exec_container(container_name, ["nc", "-z", "-v", "-w", "1", dst_ip, str(port_num)], timeout=3)

            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            cmd_output = res.stdout + res.stderr
            out_lower = cmd_output.lower()

            if res.returncode == 0 or "succeeded" in out_lower or "open" in out_lower:
                probe_status = "open"
            elif "refused" in out_lower:
                probe_status = "refused"
            else:
                probe_status = "filtered"

        elif proto == "udp":
            port_num = int(port)
            res = exec_container(container_name, ["nc", "-z", "-u", "-v", "-w", "1", dst_ip, str(port_num)], timeout=3)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            cmd_output = res.stdout + res.stderr
            probe_status = "open" if res.returncode == 0 else "filtered"

    except subprocess.TimeoutExpired:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        probe_status = "filtered"
    except Exception as e:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        probe_status = "error"
        cmd_output = str(e)

    # Fetch rule counters after probe to detect match
    rules_after = query_fw_daemon("GET", "/rules").get("rules", [])
    matched_rule = None

    if len(rules_before) == len(rules_after):
        for rb, ra in zip(rules_before, rules_after):
            try:
                pkts_diff = int(ra.get("pkts", 0)) - int(rb.get("pkts", 0))
                if pkts_diff > 0:
                    matched_rule = {
                        "num": ra.get("num"),
                        "target": ra.get("target"),
                        "protocol": ra.get("prot"),
                        "source": ra.get("source"),
                        "destination": ra.get("destination"),
                        "extra": ra.get("extra", ""),
                        "pkts_incremented": pkts_diff
                    }
                    break
            except Exception:
                continue

    return {
        "src": req.src,
        "src_container": container_name,
        "dst": dst_ip,
        "port": port,
        "proto": proto,
        "status": probe_status,
        "latency_ms": round(elapsed_ms, 2),
        "matched_rule": matched_rule,
        "output": cmd_output.strip()
    }


@app.get("/captures")
def list_captures():
    """Lists pcap packet capture files with metadata."""
    if not os.path.exists(CAPTURES_DIR):
        return {"captures": []}

    files = []
    for fname in sorted(os.listdir(CAPTURES_DIR)):
        if fname.endswith(".pcap") or ".pcap" in fname:
            fpath = os.path.join(CAPTURES_DIR, fname)
            stat = os.stat(fpath)
            files.append({
                "name": fname,
                "size_bytes": stat.st_size,
                "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime))
            })

    return {"captures": files}


@app.get("/captures/{name}")
def download_capture(name: str):
    """Download a specific pcap file with strict path traversal prevention."""
    # Disallow slashes, backslashes, or directory traversal
    if ".." in name or "/" in name or "\\" in name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename format.")

    file_path = os.path.abspath(os.path.join(CAPTURES_DIR, name))
    if not file_path.startswith(os.path.abspath(CAPTURES_DIR)) or not os.path.isfile(file_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Capture file not found.")

    return FileResponse(
        file_path,
        media_type="application/vnd.tcpdump.pcap",
        filename=name
    )


def start_server():
    """Entry point for standalone execution."""
    import uvicorn
    print("[*] Starting Network Workbench v2 Controller API on http://127.0.0.1:8080...")
    uvicorn.run(app, host="127.0.0.1", port=8080, log_level="info")


if __name__ == "__main__":
    start_server()
