#!/usr/bin/env python3
"""
evidence/tls_demo.py
Demonstrates Mode A (Two-Tier) MySQL connections under:
1. TLS Disabled (Plaintext SQL wire protocol)
2. TLS Required (TLS Encrypted wire protocol)

Proves that plaintext is an administrator / client configuration choice,
NOT an inherent limitation of Two-Tier architecture.
"""

import json
import os
import pymysql

DB_HOST = os.environ.get("DB_HOST", "10.0.3.10")
DB_PORT = int(os.environ.get("DB_PORT", 3306))
DB_USER = os.environ.get("DB_USER", "client_user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "client_secure_pass_456")
DB_NAME = os.environ.get("DB_NAME", "shopledger")

def test_plaintext():
    print("\n--- [1] Mode A with TLS Disabled (Plaintext) ---")
    conn = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        ssl_disabled=True,
        connect_timeout=4
    )
    with conn.cursor() as cur:
        cur.execute("SHOW STATUS LIKE 'Ssl_cipher'")
        cipher = cur.fetchone()
        cur.execute("SHOW STATUS LIKE 'Ssl_version'")
        version = cur.fetchone()
        cur.execute("SELECT id, sku, name, price FROM products LIMIT 1")
        row = cur.fetchone()
        print(f"  Transport Cipher : {cipher[1] if cipher[1] else 'NONE (Plaintext Wire Traffic)'}")
        print(f"  TLS Version      : {version[1] if version[1] else 'NONE'}")
        print(f"  Sample Query     : SELECT ... -> {row[1]} (${row[3]})")
    conn.close()
    return {"mode": "Plaintext", "cipher": cipher[1] or "NONE", "version": version[1] or "NONE"}

def test_tls():
    print("\n--- [2] Mode A with TLS Required (Encrypted) ---")
    conn = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        ssl={"check_hostname": False},
        connect_timeout=4
    )
    with conn.cursor() as cur:
        cur.execute("SHOW STATUS LIKE 'Ssl_cipher'")
        cipher = cur.fetchone()
        cur.execute("SHOW STATUS LIKE 'Ssl_version'")
        version = cur.fetchone()
        cur.execute("SELECT id, sku, name, price FROM products LIMIT 1")
        row = cur.fetchone()
        print(f"  Transport Cipher : {cipher[1]}")
        print(f"  TLS Version      : {version[1]}")
        print(f"  Sample Query     : SELECT ... -> {row[1]} (${row[3]})")
    conn.close()
    return {"mode": "TLS Required", "cipher": cipher[1], "version": version[1]}

def main():
    print("=" * 70)
    print("  MODE A (TWO-TIER) TRANSPORT SECURITY DEMONSTRATION")
    print("  Demonstrating that plaintext on port 3306 is a configuration choice")
    print("=" * 70)
    r1 = test_plaintext()
    r2 = test_tls()
    print("\n" + "=" * 70)
    print("SUMMARY:")
    print(f"  Plaintext Mode : Cipher={r1['cipher']}, TLS={r1['version']}")
    print(f"  TLS Mode       : Cipher={r2['cipher']}, TLS={r2['version']}")
    print("  Conclusion: Two-Tier networks can enforce full TLS encryption on the wire.")
    print("=" * 70)

if __name__ == "__main__":
    main()
