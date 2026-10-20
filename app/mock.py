#!/usr/bin/env python3
import socket
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
name = sys.argv[2] if len(sys.argv) > 2 else "app-service"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.listen(64)
print(f"[{name}] Listening on 0.0.0.0:{port}...")

while True:
    try:
        conn, addr = s.accept()
        print(f"[{name}] Connection from {addr[0]}:{addr[1]}")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nApp Tier Online\n")
        conn.close()
    except Exception as e:
        print(f"[{name}] Error: {e}")
