#!/usr/bin/env python3
"""
Firewall Control Daemon
Runs inside the firewall container to provide restricted, safe management
without granting the controller container unrestricted Docker socket access.
Listens on internal management interface and/or Unix Domain Socket /var/run/firewall/fw.sock.
Requires authentication token via X-FW-Token or Authorization: Bearer <token>.
"""

import json
import os
import subprocess
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

CURRENT_MODE = "A"
ALLOWED_MODES = {
    "A": "/opt/firewall/rules/mode-a.sh",
    "B": "/opt/firewall/rules/mode-b.sh",
    "custom": "/opt/firewall/rules/mode-custom.sh"
}
FW_TOKEN = os.environ.get("FW_TOKEN", "lab_firewall_secret_token_2026")

class FirewallHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code, data):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def _verify_auth(self):
        token_header = self.headers.get("X-FW-Token")
        auth_header = self.headers.get("Authorization", "")
        bearer_token = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""
        provided = token_header or bearer_token
        if provided != FW_TOKEN:
            self._send_json(401, {"error": "Unauthorized: Invalid or missing firewall control token"})
            return False
        return True

    def _detect_mode(self):
        global CURRENT_MODE
        try:
            if os.path.exists("/var/run/firewall/mode"):
                with open("/var/run/firewall/mode", "r") as f:
                    m = f.read().strip()
                    if m in ALLOWED_MODES:
                        CURRENT_MODE = m
                        return CURRENT_MODE
        except Exception:
            pass
        try:
            res = subprocess.run(["iptables", "-S", "FORWARD"], capture_output=True, text=True, timeout=2)
            if "[FW-DROP-B]" in res.stdout:
                CURRENT_MODE = "B"
            elif "[FW-DROP-A]" in res.stdout:
                CURRENT_MODE = "A"
            elif "[FW-CUSTOM-DROP]" in res.stdout:
                CURRENT_MODE = "custom"
        except Exception:
            pass
        return CURRENT_MODE

    def do_GET(self):
        global CURRENT_MODE
        if self.path == "/health":
            self._send_json(200, {"status": "healthy"})
            return

        if not self._verify_auth():
            return

        self._detect_mode()

        if self.path == "/status":
            rules = self._get_parsed_rules()
            self._send_json(200, {
                "mode": CURRENT_MODE,
                "status": "active",
                "rules_count": len(rules),
                "ip_forward": 1
            })
        elif self.path == "/rules":
            rules = self._get_parsed_rules()
            self._send_json(200, {
                "mode": CURRENT_MODE,
                "rules": rules
            })
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        global CURRENT_MODE
        if not self._verify_auth():
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            payload = json.loads(body)
        except Exception:
            payload = {}

        if self.path == "/mode":
            mode = str(payload.get("mode", "")).strip()
            if mode not in ALLOWED_MODES:
                self._send_json(400, {"error": f"Invalid mode. Must be one of: {list(ALLOWED_MODES.keys())}"})
                return
            script = ALLOWED_MODES[mode]
            res = subprocess.run(["/bin/bash", script], capture_output=True, text=True)
            if res.returncode != 0:
                self._send_json(500, {"error": "Failed to apply mode script", "details": res.stderr})
                return
            CURRENT_MODE = mode
            self._send_json(200, {
                "success": True,
                "mode": CURRENT_MODE,
                "output": res.stdout.strip()
            })
        elif self.path == "/rules/custom":
            rules_list = payload.get("rules", [])
            if not isinstance(rules_list, list):
                self._send_json(400, {"error": "rules must be a list"})
                return

            valid_ips = {"192.168.1.20", "10.0.1.10", "10.0.2.10", "10.0.3.10", "0.0.0.0/0", "any"}
            valid_ports = {443, 5000, 3306, 22, 53, 80}
            valid_actions = {"ACCEPT", "DROP", "REJECT"}
            valid_protos = {"tcp", "udp", "icmp"}

            generated_commands = []
            for r in rules_list:
                src = str(r.get("source", "")).strip()
                dst = str(r.get("destination", "")).strip()
                port = r.get("port")
                proto = str(r.get("proto", "tcp")).lower().strip()
                action = str(r.get("action", "ACCEPT")).upper().strip()

                if src not in valid_ips or dst not in valid_ips:
                    self._send_json(400, {"error": f"Invalid IP address: {src} -> {dst}"})
                    return
                if action not in valid_actions:
                    self._send_json(400, {"error": f"Invalid action: {action}"})
                    return
                if proto not in valid_protos:
                    self._send_json(400, {"error": f"Invalid protocol: {proto}"})
                    return

                cmd = ["iptables", "-A", "FORWARD"]
                if src != "any" and src != "0.0.0.0/0":
                    cmd += ["-s", src]
                if dst != "any" and dst != "0.0.0.0/0":
                    cmd += ["-d", dst]
                cmd += ["-p", proto]
                if port and port != "any":
                    try:
                        p = int(port)
                        if p not in valid_ports:
                            self._send_json(400, {"error": f"Port {p} not allowed in lab presets"})
                            return
                        cmd += ["--dport", str(p)]
                    except ValueError:
                        self._send_json(400, {"error": f"Invalid port value: {port}"})
                        return
                cmd += ["-j", action]
                generated_commands.append(cmd)

            subprocess.run(["/bin/bash", "/opt/firewall/rules/mode-custom.sh"], check=True)
            for cmd in generated_commands:
                subprocess.run(["iptables", "-I", "FORWARD", "3"] + cmd[3:], check=True)

            CURRENT_MODE = "custom"
            self._send_json(200, {
                "success": True,
                "mode": "custom",
                "rules_applied": len(generated_commands)
            })
        else:
            self._send_json(404, {"error": "Not found"})

    def _get_parsed_rules(self):
        res = subprocess.run(["iptables", "-L", "FORWARD", "-v", "-n", "--line-numbers"],
                             capture_output=True, text=True)
        if res.returncode != 0:
            return []
        lines = res.stdout.strip().splitlines()
        rules = []
        for line in lines[2:]:
            parts = line.split()
            if len(parts) >= 9:
                rule = {
                    "num": parts[0],
                    "pkts": parts[1],
                    "bytes": parts[2],
                    "target": parts[3],
                    "prot": parts[4],
                    "opt": parts[5],
                    "in": parts[6],
                    "out": parts[7],
                    "source": parts[8],
                    "destination": parts[9],
                    "extra": " ".join(parts[10:]) if len(parts) > 10 else ""
                }
                rules.append(rule)
        return rules

    def log_message(self, format, *args):
        return

def run_server():
    os.makedirs("/var/run/firewall", exist_ok=True)
    # Bind to management IP or 127.0.0.1 (not client reachable)
    bind_ip = os.environ.get("FW_BIND_IP", "172.28.0.254")
    try:
        httpd = HTTPServer((bind_ip, 9099), FirewallHandler)
        print(f"[firewall-daemon] Internal control daemon listening on {bind_ip}:9099...")
        httpd.serve_forever()
    except Exception as e:
        print(f"[firewall-daemon] Fallback binding to 127.0.0.1:9099 ({e})")
        httpd = HTTPServer(("127.0.0.1", 9099), FirewallHandler)
        httpd.serve_forever()

if __name__ == "__main__":
    run_server()
