#!/usr/bin/env python3
"""
Network Workbench v2 — Lab Orchestrator (lab.py)
Cross-platform lab automation tool for Windows (PowerShell/WSL), Linux, and macOS.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def get_docker_cmd():
    """Detect docker compose executable (either native or via WSL)."""
    if shutil.which("docker"):
        # Native docker available
        return ["docker", "compose"]
    elif shutil.which("wsl"):
        # Run via WSL default user
        return ["wsl", "-d", "Ubuntu", "-e", "docker", "compose"]
    else:
        print("[!] Error: neither docker nor wsl was found in PATH.")
        sys.exit(1)

def run_wsl_root(cmd):
    """Run a root command in WSL if WSL is available."""
    if shutil.which("wsl"):
        subprocess.run(["wsl", "-u", "root", "-d", "Ubuntu", "-e", "bash", "-c", cmd], check=False)

def ensure_host_sysctls():
    """Ensure Linux host bridge filter doesn't drop inter-tier internal packets."""
    run_wsl_root("/usr/sbin/sysctl -w net.bridge.bridge-nf-call-iptables=0 2>/dev/null || true")

def run_compose(args):
    """Execute docker compose with the given arguments."""
    ensure_host_sysctls()
    docker_cmd = get_docker_cmd()
    
    # Run in BASE_DIR context
    if docker_cmd[0] == "wsl":
        # Convert path to WSL mount
        wsl_dir = BASE_DIR.replace("\\", "/").replace("F:", "/mnt/f").replace("C:", "/mnt/c")
        full_cmd = ["wsl", "-d", "Ubuntu", "-e", "docker", "compose", "-f", f"{wsl_dir}/docker-compose.yml"] + args
    else:
        full_cmd = docker_cmd + ["-f", os.path.join(BASE_DIR, "docker-compose.yml")] + args
        
    print(f">> {' '.join(full_cmd)}")
    return subprocess.run(full_cmd)

def exec_in_container(container, cmd):
    """Execute a command inside a specific container."""
    docker_cmd = get_docker_cmd()
    if docker_cmd[0] == "wsl":
        full_cmd = ["wsl", "-d", "Ubuntu", "-e", "docker", "exec", container] + cmd
    else:
        full_cmd = ["docker", "exec", container] + cmd
    return subprocess.run(full_cmd, capture_output=True, text=True)

def cmd_start(args):
    """Build and start the network lab."""
    print("=== Starting Network Workbench v2 Lab ===")
    os.makedirs(os.path.join(BASE_DIR, "captures"), exist_ok=True)
    run_compose(["up", "-d", "--build"])
    time.sleep(2)
    # Default to Mode A
    cmd_mode_a(args)
    print("\n[+] Lab running! All 4 isolated tier networks active.")
    cmd_status(args)

def cmd_stop(args):
    """Stop the network lab and remove containers."""
    print("=== Stopping Network Workbench v2 Lab ===")
    run_compose(["down"])
    print("[+] Lab stopped.")

def cmd_mode_a(args):
    """Switch firewall to Mode A (Two-Tier direct client-database)."""
    print("\n>>> Switching to MODE A (Two-Tier Architecture)...")
    res = exec_in_container("lab_firewall", ["/bin/bash", "/opt/firewall/rules/mode-a.sh"])
    print(res.stdout)
    if res.stderr:
        print(f"[err] {res.stderr}")

def cmd_mode_b(args):
    """Switch firewall to Mode B (Three-Tier segmented)."""
    print("\n>>> Switching to MODE B (Three-Tier Architecture)...")
    res = exec_in_container("lab_firewall", ["/bin/bash", "/opt/firewall/rules/mode-b.sh"])
    print(res.stdout)
    if res.stderr:
        print(f"[err] {res.stderr}")

def cmd_mode_custom(args):
    """Switch firewall to Mode Custom."""
    print("\n>>> Switching to MODE Custom...")
    res = exec_in_container("lab_firewall", ["/bin/bash", "/opt/firewall/rules/mode-custom.sh"])
    print(res.stdout)

def cmd_status(args):
    """Display container status and active firewall rules."""
    print("\n=== Active Containers ===")
    docker_cmd = get_docker_cmd()
    if docker_cmd[0] == "wsl":
        subprocess.run(["wsl", "-u", "root", "-d", "Ubuntu", "-e", "docker", "ps", "--format", "table {{.Names}}\t{{.Status}}\t{{.Ports}}"])
    else:
        subprocess.run(["docker", "ps", "--format", "table {{.Names}}\t{{.Status}}\t{{.Ports}}"])

    print("\n=== Firewall FORWARD Policy & Rule Counters ===")
    res = exec_in_container("lab_firewall", ["iptables", "-L", "FORWARD", "-v", "-n", "--line-numbers"])
    print(res.stdout)

def run_matrix_scans(mode_name):
    """Scan between each tier and print a cross-tier matrix for the current mode."""
    # Define test probes: (src_container, src_label, target_ip, target_port, target_label, expected_mode_a, expected_mode_b)
    probes = [
        # From Client
        ("lab_client", "Client (192.168.1.20)", "10.0.3.10", 3306, "DB :3306", "ALLOW", "DENY"),
        ("lab_client", "Client (192.168.1.20)", "10.0.1.10", 443,  "Web :443", "DENY",  "ALLOW"),
        ("lab_client", "Client (192.168.1.20)", "10.0.2.10", 5000, "App :5000", "DENY", "DENY"),
        ("lab_client", "Client (192.168.1.20)", "192.168.1.254", 9099, "FW :9099", "DENY", "DENY"),
        # From Web
        ("lab_web",    "Web (10.0.1.10)",      "10.0.2.10", 5000, "App :5000", "DENY",  "ALLOW"),
        ("lab_web",    "Web (10.0.1.10)",      "10.0.3.10", 3306, "DB :3306",  "DENY",  "DENY"),
        ("lab_web",    "Web (10.0.1.10)",      "192.168.1.20", 8080, "Client", "DENY",  "DENY"),
        # From App
        ("lab_app",    "App (10.0.2.10)",      "10.0.3.10", 3306, "DB :3306",  "DENY",  "ALLOW"),
        ("lab_app",    "App (10.0.2.10)",      "10.0.1.10", 443,  "Web :443",  "DENY",  "DENY"),
        # From DB
        ("lab_db",     "DB (10.0.3.10)",       "10.0.2.10", 5000, "App :5000", "DENY",  "DENY"),
        ("lab_db",     "DB (10.0.3.10)",       "192.168.1.20", 3306, "Client", "DENY",  "DENY"),
    ]

    print(f"\n+-----------------------------------------------------------------------------------------+")
    print(f"| {mode_name:^87} |")
    print(f"+-------------------------+---------------+----------+----------+-------------------------+")
    print(f"| Source Tier             | Target Tier   | Expected | Observed | Verification Status     |")
    print(f"+-------------------------+---------------+----------+----------+-------------------------+")

    all_passed = True
    for src, src_lbl, dst_ip, dst_port, dst_lbl, exp_a, exp_b in probes:
        expected = exp_a if "mode a" in mode_name.lower() else exp_b
        res = exec_in_container(src, ["nc", "-z", "-w", "1", dst_ip, str(dst_port)])
        out = (res.stdout + res.stderr).lower()
        # Nonzero exit code or no open message indicates filtered/denied
        is_open = (res.returncode == 0) or ("succeeded" in out) or ("open" in out)
        observed = "ALLOW" if is_open else "DENY"
        passed = (observed == expected)
        if not passed:
            all_passed = False
        badge = "[ PASS ]" if passed else "[ FAIL ]"
        print(f"| {src_lbl:23} | {dst_lbl:13} | {expected:8} | {observed:8} | {badge:23} |")

    print(f"+-------------------------+---------------+----------+----------+-------------------------+")
    return all_passed

def cmd_verify(args):
    """Run full network verification (ping, nc, nmap) in both Mode A and Mode B."""
    ensure_host_sysctls()
    print("\n" + "="*70)
    print("     NETWORK WORKBENCH v2 — MULTI-TIER VERIFICATION SUITE")
    print("="*70)

    # 1. Verification under Mode A
    cmd_mode_a(args)
    time.sleep(1)
    print("\n[TEST 1] Testing ICMP Ping from Client (192.168.1.20) in Mode A:")
    for target_name, target_ip in [("Router", "192.168.1.254"), ("Web", "10.0.1.10"), ("App", "10.0.2.10"), ("DB", "10.0.3.10")]:
        res = exec_in_container("lab_client", ["ping", "-c", "2", "-W", "1", target_ip])
        loss = ("0% loss" in res.stdout or "0% packet loss" in res.stdout)
        status = "PASSED (0% packet loss)" if loss else "FAILED"
        print(f"  -> Ping {target_name:7} ({target_ip:14}): {status}")

    print("\n[TEST 1b] Testing Traceroute from Client to Database Server (10.0.3.10):")
    res_trace = exec_in_container("lab_client", ["traceroute", "-I", "-n", "-m", "3", "-w", "1", "10.0.3.10"])
    print(res_trace.stdout)

    print("\n[TEST 1c] Security Audit: Verifying fw_daemon (:9099) is Non-Reachable from Client:")
    res_audit = exec_in_container("lab_client", ["nmap", "-Pn", "-p", "9099", "192.168.1.254", "10.0.1.254", "10.0.2.254", "10.0.3.254"])
    print(res_audit.stdout)

    print("\n[TEST 2] Cross-Tier Isolation Matrix in Mode A (Two-Tier):")
    run_matrix_scans("MODE A — Two-Tier (Client -> DB :3306 Allowed)")

    # 2. Verification under Mode B
    cmd_mode_b(args)
    time.sleep(1)
    print("\n[TEST 3] Cross-Tier Isolation Matrix in Mode B (Three-Tier):")
    run_matrix_scans("MODE B — Three-Tier (Web:443 -> App:5000 -> DB:3306 Allowed)")

    print("\n[TEST 4] Real nmap from Client against Database Server (10.0.3.10) in Mode B:")
    res_nmap_b_db = exec_in_container("lab_client", ["nmap", "-Pn", "-p", "443,5000,3306,22", "10.0.3.10"])
    print(res_nmap_b_db.stdout)

    print("\n[TEST 5] Real nmap from Client against Web Server (10.0.1.10) in Mode B:")
    res_nmap_b_web = exec_in_container("lab_client", ["nmap", "-Pn", "-p", "443,5000,3306,22", "10.0.1.10"])
    print(res_nmap_b_web.stdout)

    print("\n" + "="*70)
    print("     ALL VERIFICATION CHECKS COMPLETED")
    print("="*70)

def main():
    parser = argparse.ArgumentParser(description="Network Workbench v2 Lab Orchestrator")
    subparsers = parser.add_subparsers(dest="command", help="Lab commands")

    subparsers.add_parser("start", help="Build and start lab containers")
    subparsers.add_parser("stop", help="Stop and remove lab containers")
    subparsers.add_parser("mode-a", help="Switch firewall to Mode A (Two-Tier)")
    subparsers.add_parser("mode-b", help="Switch firewall to Mode B (Three-Tier)")
    subparsers.add_parser("mode-custom", help="Switch firewall to Mode Custom")
    subparsers.add_parser("status", help="Show lab status and firewall counters")
    subparsers.add_parser("verify", help="Run ping, nc, and nmap verification across modes")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "start": cmd_start,
        "stop": cmd_stop,
        "mode-a": cmd_mode_a,
        "mode-b": cmd_mode_b,
        "mode-custom": cmd_mode_custom,
        "status": cmd_status,
        "verify": cmd_verify
    }
    dispatch[args.command](args)

if __name__ == "__main__":
    main()
