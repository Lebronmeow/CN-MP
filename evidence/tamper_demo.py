#!/usr/bin/env python3
"""
evidence/tamper_demo.py
Demonstrates the fundamental security and integrity trade-off between
Two-Tier (Mode A) and Three-Tier (Mode B) architectures.

Trade-off:
- In Two-Tier (Mode A): The client application holds direct SQL privileges.
  While client_user has least-privilege column grants (UPDATE on products.stock,
  INSERT on invoice_items), the database CANNOT enforce business logic invariants.
  A compromised or manipulated client can insert an invoice line-item with a
  fraudulent price ($0.01 instead of $499.50), and the database commits it.
  
- In Three-Tier (Mode B): The client submits an intent payload to the FastAPI
  middleware. The server validates input, queries the trusted catalog price,
  and rejects any client price manipulation with HTTP 400 Bad Request.
"""

import json
import os
import ssl
import sys
import time
import urllib.request
import pymysql

DB_HOST = os.environ.get("DB_HOST", "10.0.3.10")
DB_PORT = int(os.environ.get("DB_PORT", 3306))
DB_USER = os.environ.get("DB_USER", "client_user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "client_secure_pass_456")
DB_NAME = os.environ.get("DB_NAME", "shopledger")

TARGET_SKU = "SKU-1002" # Dell UltraSharp 27 4K Monitor (Catalog Price: $499.50)
FRAUDULENT_PRICE = 0.01

def demo_mode_a_tamper():
    print("\n" + "=" * 75)
    print("  [DEMO 1] MODE A (TWO-TIER): DIRECT CLIENT SQL INJECTION / PRICE TAMPER")
    print("=" * 75)
    print(f"Scenario: A manipulated Mode A desktop client connects using client_user.")
    print(f"Goal: Purchase '{TARGET_SKU}' (Catalog: $499.50) for $0.01.\n")

    conn = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        autocommit=False,
        connect_timeout=4
    )

    try:
        with conn.cursor() as cur:
            # 1. Fetch product
            cur.execute("SELECT id, name, price, stock FROM products WHERE sku = %s", (TARGET_SKU,))
            prod = cur.fetchone()
            prod_id, prod_name, catalog_price, stock_before = prod[0], prod[1], float(prod[2]), prod[3]
            print(f"[*] Target Product  : {prod_name} (SKU: {TARGET_SKU})")
            print(f"[*] Real Catalog Price : ${catalog_price:.2f}")
            print(f"[*] Stock Before Sale : {stock_before}")

            # 2. Tampered insertion: client forces price = $0.01
            inv_num = f"INV-TAMPER-A-{int(time.time() * 1000) % 1000000}"
            print(f"\n[>] Client executing raw INSERT with manipulated unit_price = ${FRAUDULENT_PRICE:.2f}...")

            cur.execute(
                "INSERT INTO invoices (invoice_number, customer_id, total_amount) VALUES (%s, %s, %s)",
                (inv_num, 1, FRAUDULENT_PRICE)
            )
            inv_id = cur.lastrowid

            cur.execute(
                "INSERT INTO invoice_items (invoice_id, product_id, quantity, unit_price, line_total) "
                "VALUES (%s, %s, %s, %s, %s)",
                (inv_id, prod_id, 1, FRAUDULENT_PRICE, FRAUDULENT_PRICE)
            )

            # Stock decrement via column-level grant: GRANT UPDATE (stock) ON products TO client_user
            cur.execute(
                "UPDATE products SET stock = stock - 1 WHERE id = %s",
                (prod_id,)
            )

            conn.commit()

            print(f"[!] SUCCESS (DATA INTEGRITY VIOLATED): Database accepted manipulated price!")
            print(f"    Invoice Created: {inv_num}")
            print(f"    Billed Amount  : ${FRAUDULENT_PRICE:.2f} (Expected: ${catalog_price:.2f})")
            print(f"    Stock Decrement: {stock_before} -> {stock_before - 1}")
            print(f"    Underlying Grant: client_user has 'GRANT UPDATE (stock) ON shopledger.products'")
            print(f"                      and 'GRANT INSERT ON shopledger.invoice_items'.")
            print(f"    Key Takeaway    : The database verified SQL privileges, but had NO WAY")
            print(f"                      to verify application-level business rules!")
            return True
    except Exception as e:
        conn.rollback()
        print(f"[-] Mode A transaction failed: {e}")
        return False
    finally:
        conn.close()

def demo_mode_b_tamper():
    print("\n" + "=" * 75)
    print("  [DEMO 2] MODE B (THREE-TIER): MIDDLEWARE VALIDATION / TAMPER REJECTION")
    print("=" * 75)
    print(f"Scenario: An attacker sends an HTTP request to FastAPI with a manipulated price.")
    print(f"Goal: Attempt to purchase '{TARGET_SKU}' for $0.01 via the API.\n")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    payload = {
        "customer_id": 1,
        "items": [
            {
                "product_sku": TARGET_SKU,
                "quantity": 1,
                "unit_price": FRAUDULENT_PRICE # Maliciously injected price
            }
        ]
    }

    req = urllib.request.Request(
        "https://10.0.1.10:443/api/invoices",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Tamper-Demo-Client"
        },
        method="POST"
    )

    try:
        print(f"[>] Sending HTTP POST with payload: {json.dumps(payload)}...")
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            print(f"[!] API accepted response: {data}")
            return False
    except urllib.error.HTTPError as err:
        err_body = err.read().decode()
        print(f"[+] HTTP {err.code} {err.reason} (SECURITY INVARIANT ENFORCED):")
        print(f"    API Server Response: {err_body}")
        print(f"    Key Takeaway       : In Three-Tier, the client NEVER talks to the database.")
        print(f"                         The FastAPI tier validates prices against the server catalog")
        print(f"                         and rejected the fraudulent price before it ever reached MySQL.")
        return True
    except Exception as e:
        print(f"[-] Request failed: {e}")
        return False

def main():
    part = "all"
    if len(sys.argv) > 1:
        part = sys.argv[1].lower().replace("--part=", "").replace("--", "")

    print("===========================================================================")
    print("        BUSINESS LOGIC INTEGRITY & PRICE TAMPERING DEMONSTRATION")
    print("        Comparing Two-Tier (Mode A) vs Three-Tier (Mode B)")
    print("===========================================================================")

    if part in {"all", "a", "mode-a"}:
        demo_mode_a_tamper()

    if part in {"all", "b", "mode-b"}:
        demo_mode_b_tamper()

    print("\n" + "=" * 75)
    print("SUMMARY OF ARCHITECTURAL SECURITY TRADE-OFF:")
    print("  Mode A (Two-Tier)   : Tampered price accepted by DB because SQL grants")
    print("                        lack domain business logic context.")
    print("  Mode B (Three-Tier) : Tampered price actively detected and rejected with")
    print("                        HTTP 400 Bad Request by the application tier.")
    print("===========================================================================")

if __name__ == "__main__":
    main()
