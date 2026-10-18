#!/usr/bin/env python3
"""
Computer Networks Mini-Project: Secure 3-Tier Web Application
Standalone Local Runner

Runs the complete application locally without Docker, binding on BOTH port 5000
and port 8000 simultaneously so that all browser tabs, bookmarks, and links work seamlessly.
"""

import os
import sys
import threading
import webbrowser
from werkzeug.serving import run_simple

# Add backend directory to Python module search path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
sys.path.insert(0, BACKEND_DIR)

from app import app
import db

def print_banner(primary_port, alt_port):
    print("=" * 75)
    print("  COMPUTER NETWORKS MINI-PROJECT: SECURE 3-TIER WEB APPLICATION")
    print("=" * 75)
    print("  [Architecture Deployment]")
    print(f"  * Tier 1 (Web): Static Assets & Ingress (http://localhost:{primary_port} and http://localhost:{alt_port})")
    print(f"  * Tier 2 (App): Flask REST API & RBAC (Routes: /api/auth, /api/students, /api/security)")
    
    db_stat = db.get_db_status()
    print(f"  * Tier 3 (DB):  {db_stat['dialect']} Database ({db_stat['host']}) - Isolated Storage")
    print("-" * 75)
    print("  [Demo Credentials]")
    print("  * Admin:   admin   / Admin@123   (Full CRUD & Security Audit access)")
    print("  * Student: student / Student@123 (Read-only student directory & profile)")
    print("=" * 75)
    print(f"  >> Primary URL: http://localhost:{primary_port}#portal")
    print(f"  >> Alt URL:     http://localhost:{alt_port}#portal")
    print("=" * 75)

def run_server(port):
    try:
        run_simple("0.0.0.0", port, app, threaded=True)
    except Exception as e:
        print(f"[Server Warning] Could not bind to port {port}: {e}")

if __name__ == "__main__":
    primary_port = int(os.environ.get("PORT", 5000))
    alt_port = 8000

    print_banner(primary_port, alt_port)

    # Start primary port in a background thread if running dual ports
    t = threading.Thread(target=run_server, args=(primary_port,), daemon=True)
    t.start()

    # Auto-open browser if requested
    if "--open" in sys.argv:
        webbrowser.open(f"http://localhost:{primary_port}#portal")

    # Run alternate port on main thread
    run_server(alt_port)
