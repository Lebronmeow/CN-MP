#!/usr/bin/env python3
"""
ShopLedger Mode A CLI Client
Direct-to-Database Client-Server Architecture (Two-Tier)
Connects directly to MySQL 8.0 on port 3306 using client_user restricted credentials.
"""

import argparse
import os
import sys
import time
from datetime import datetime
import pymysql
from pymysql.cursors import DictCursor

DB_HOST = os.environ.get("DB_HOST", "10.0.3.10")
DB_PORT = int(os.environ.get("DB_PORT", 3306))
DB_USER = os.environ.get("DB_USER", "client_user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "client_secure_pass_456")
DB_NAME = os.environ.get("DB_NAME", "shopledger")

def get_connection():
    try:
        return pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            cursorclass=DictCursor,
            connect_timeout=4,
            autocommit=False
        )
    except Exception as e:
        print(f"[!] Database Connection Error ({DB_HOST}:{DB_PORT}): {e}", file=sys.stderr)
        sys.exit(1)

def cmd_products(args):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            sql = "SELECT id, sku, name, category, CAST(price AS DOUBLE) as price, stock FROM products"
            params = []
            if args.search:
                sql += " WHERE name LIKE %s OR sku LIKE %s"
                params.extend([f"%{args.search}%", f"%{args.search}%"])
            sql += " ORDER BY id ASC LIMIT 50"
            cur.execute(sql, params)
            rows = cur.fetchall()

            print(f"\n{'SKU':<12} {'NAME':<35} {'CATEGORY':<16} {'PRICE ($)':>10} {'STOCK':>8}")
            print("-" * 85)
            for r in rows:
                print(f"{r['sku']:<12} {r['name'][:34]:<35} {r['category']:<16} {r['price']:>10.2f} {r['stock']:>8}")
            print(f"\nTotal: {len(rows)} products displayed.")
    finally:
        conn.close()

def cmd_low_stock(args):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT sku, name, category, CAST(price AS DOUBLE) as price, stock FROM products WHERE stock <= %s ORDER BY stock ASC",
                (args.threshold,)
            )
            rows = cur.fetchall()
            print(f"\n=== LOW STOCK REPORT (Threshold <= {args.threshold}) ===")
            print(f"{'SKU':<12} {'NAME':<35} {'CATEGORY':<16} {'STOCK':>8}")
            print("-" * 75)
            for r in rows:
                print(f"{r['sku']:<12} {r['name'][:34]:<35} {r['category']:<16} {r['stock']:>8}")
            print(f"\nWarning: {len(rows)} items require reordering.")
    finally:
        conn.close()

def cmd_customers(args):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, email, phone FROM customers ORDER BY id ASC")
            rows = cur.fetchall()
            print(f"\n{'ID':<5} {'NAME':<32} {'EMAIL':<30} {'PHONE':<15}")
            print("-" * 85)
            for r in rows:
                print(f"{r['id']:<5} {r['name']:<32} {r['email']:<30} {r['phone']:<15}")
    finally:
        conn.close()

def cmd_create_invoice(args):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 1. Check customer
            cur.execute("SELECT id, name FROM customers WHERE id = %s", (args.customer,))
            cust = cur.fetchone()
            if not cust:
                print(f"[!] Customer ID {args.customer} not found.", file=sys.stderr)
                return

            # 2. Check product
            cur.execute("SELECT id, sku, name, price, stock FROM products WHERE sku = %s FOR UPDATE", (args.sku,))
            prod = cur.fetchone()
            if not prod:
                print(f"[!] Product SKU '{args.sku}' not found.", file=sys.stderr)
                return
            if prod["stock"] < args.quantity:
                print(f"[!] Insufficient stock for {prod['name']}. Available: {prod['stock']}, Requested: {args.quantity}", file=sys.stderr)
                return

            unit_price = float(prod["price"])
            total_amount = unit_price * args.quantity
            inv_number = f"INV-2026-CLI-{int(time.time() * 1000) % 1000000:06d}"

            # 3. Insert invoice
            cur.execute(
                "INSERT INTO invoices (invoice_number, customer_id, total_amount) VALUES (%s, %s, %s)",
                (inv_number, args.customer, total_amount)
            )
            inv_id = cur.lastrowid

            # 4. Insert items & decrement stock
            cur.execute(
                "INSERT INTO invoice_items (invoice_id, product_id, quantity, unit_price, line_total) VALUES (%s, %s, %s, %s, %s)",
                (inv_id, prod["id"], args.quantity, unit_price, total_amount)
            )
            cur.execute(
                "UPDATE products SET stock = stock - %s WHERE id = %s",
                (args.quantity, prod["id"])
            )

            conn.commit()
            print(f"\n[+] Invoice Created Successfully (Direct Mode A Transaction):")
            print(f"    Invoice Number : {inv_number}")
            print(f"    Customer       : {cust['name']}")
            print(f"    Item           : {prod['name']} (x{args.quantity})")
            print(f"    Total Amount   : ${total_amount:.2f}")
            print(f"    Remaining Stock: {prod['stock'] - args.quantity}")
    except Exception as e:
        conn.rollback()
        print(f"[!] Transaction failed and rolled back: {e}", file=sys.stderr)
    finally:
        conn.close()

def cmd_sales(args):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            sql = """
                SELECT DATE(created_at) as sale_date,
                       COUNT(id) as total_invoices,
                       CAST(SUM(total_amount) AS DOUBLE) as revenue
                FROM invoices
                GROUP BY DATE(created_at)
                ORDER BY sale_date DESC LIMIT 10
            """
            cur.execute(sql)
            rows = cur.fetchall()
            print(f"\n{'DATE':<14} {'TOTAL INVOICES':<16} {'DAILY REVENUE ($)':>18}")
            print("-" * 52)
            for r in rows:
                print(f"{str(r['sale_date']):<14} {r['total_invoices']:<16} {r['revenue']:>18.2f}")
    finally:
        conn.close()

def main():
    parser = argparse.ArgumentParser(description="ShopLedger Mode A (Two-Tier) Direct Database Client")
    subparsers = parser.add_subparsers(dest="subcommand", help="Available operations")

    p_prod = subparsers.add_parser("products", help="List and search inventory catalog")
    p_prod.add_argument("--search", type=str, help="Search filter for product name or SKU")

    p_low = subparsers.add_parser("low-stock", help="View low inventory items requiring restock")
    p_low.add_argument("--threshold", type=int, default=10, help="Stock limit threshold (default: 10)")

    subparsers.add_parser("customers", help="List all customers")

    p_inv = subparsers.add_parser("invoice", help="Create a direct billing invoice with stock decrement")
    p_inv.add_argument("--customer", type=int, required=True, help="Customer ID")
    p_inv.add_argument("--sku", type=str, required=True, help="Product SKU (e.g. SKU-1001)")
    p_inv.add_argument("--quantity", type=int, default=1, help="Quantity to bill")

    subparsers.add_parser("sales", help="Daily sales summary report")

    args = parser.parse_args()
    if not args.subcommand:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "products": cmd_products,
        "low-stock": cmd_low_stock,
        "customers": cmd_customers,
        "invoice": cmd_create_invoice,
        "sales": cmd_sales
    }
    dispatch[args.subcommand](args)

if __name__ == "__main__":
    main()
