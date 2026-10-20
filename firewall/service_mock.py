#!/usr/bin/env python3
"""
Simple TCP Service Mock
Listens on the assigned port and accepts TCP connections for network testing.
"""
import os
import socket
import sys

port = int(os.environ.get("SERVICE_PORT", sys.argv[1] if len(sys.argv) > 1 else 8080))
name = os.environ.get("SERVICE_NAME", "mock-service")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.listen(128)
print(f"[{name}] Listening on 0.0.0.0:{port}...")

while True:
    try:
        conn, addr = s.accept()
        print(f"[{name}] Accepted connection from {addr[0]}:{addr[1]}")
        conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n{name} OK\n".encode("utf-8"))
        conn.close()
    except Exception as e:
        print(f"[{name}] Error: {e}")
