#!/usr/bin/env python3
"""
Standalone Demo HTTP Server for Network Workbench 2.0
Usage:
    python demo_server.py [port]

Default port: 8080
Used to demonstrate:
1. Reachable TCP connection when running.
2. Connection Refused (RST) when terminated (Ctrl+C).
"""

import sys
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({
            "service": "Network Workbench 2.0 Demo Web Service",
            "status": "ONLINE",
            "port": self.server.server_port,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }, indent=2).encode("utf-8")
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {self.client_address[0]} - {args[0]}")

def run():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server_address = ("127.0.0.1", port)
    
    try:
        httpd = HTTPServer(server_address, DemoHandler)
        print("=" * 60)
        print(f" [DEMO SERVER] Running on http://127.0.0.1:{port}")
        print(" Used for Network Workbench 2.0 Connectivity Demonstration:")
        print(" 1. Run diagnostics on 127.0.0.1:{port} -> status: REACHABLE")
        print(" 2. Press Ctrl+C to stop -> status: CONNECTION REFUSED (RST)")
        print("=" * 60)
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[DEMO SERVER] Shutting down. Port closed.")
    except Exception as e:
        print(f"[ERROR] Could not start server: {e}")

if __name__ == "__main__":
    run()
