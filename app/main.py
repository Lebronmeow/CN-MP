import os
import time
from typing import List, Optional
from datetime import datetime

import pymysql
from pymysql.cursors import DictCursor
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Database configuration (app_user least-privilege credentials)
DB_HOST = os.environ.get("DB_HOST", "10.0.3.10")
DB_PORT = int(os.environ.get("DB_PORT", 3306))
DB_USER = os.environ.get("DB_USER", "app_user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "app_secure_pass_123")
DB_NAME = os.environ.get("DB_NAME", "shopledger")

app = FastAPI(
    title="ShopLedger API",
    description="Three-Tier Application Logic Service for Inventory and Billing",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    """Establish connection to MySQL using app_user credentials."""
    retries = 3
    while retries > 0:
        try:
            return pymysql.connect(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
                cursorclass=DictCursor,
                connect_timeout=3,
                autocommit=False
            )
        except Exception as e:
            retries -= 1
            if retries == 0:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=f"Database connection failed: {e}"
                )
            time.sleep(1)

# Pydantic Models
class InvoiceItemCreate(BaseModel):
    product_sku: str
    quantity: int = Field(gt=0, description="Quantity must be greater than zero")
    unit_price: Optional[float] = Field(None, description="Optional client-submitted unit price for validation")

class InvoiceCreate(BaseModel):
    customer_id: int
    items: List[InvoiceItemCreate]

@app.get("/health")
def health():
    return {"status": "healthy", "tier": "application", "service": "ShopLedger FastAPI"}

@app.get("/api/products")
def list_products(search: Optional[str] = None, category: Optional[str] = None):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            sql = "SELECT id, sku, name, category, CAST(price AS DOUBLE) as price, stock, created_at FROM products WHERE 1=1"
            params = []
            if search:
                sql += " AND (name LIKE %s OR sku LIKE %s)"
                params.extend([f"%{search}%", f"%{search}%"])
            if category:
                sql += " AND category = %s"
                params.append(category)
            sql += " ORDER BY id ASC"
            cur.execute(sql, params)
            return cur.fetchall()
    finally:
        conn.close()

@app.get("/api/products/low-stock")
def low_stock_report(threshold: int = 10):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            sql = "SELECT id, sku, name, category, CAST(price AS DOUBLE) as price, stock FROM products WHERE stock <= %s ORDER BY stock ASC"
            cur.execute(sql, (threshold,))
            return cur.fetchall()
    finally:
        conn.close()

@app.get("/api/customers")
def list_customers():
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, email, phone, address FROM customers ORDER BY id ASC")
            return cur.fetchall()
    finally:
        conn.close()

@app.get("/api/invoices")
def list_invoices(limit: int = 50):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            sql = """
                SELECT i.id, i.invoice_number, i.customer_id, c.name as customer_name,
                       CAST(i.total_amount AS DOUBLE) as total_amount, i.created_at
                FROM invoices i
                JOIN customers c ON i.customer_id = c.id
                ORDER BY i.id DESC LIMIT %s
            """
            cur.execute(sql, (limit,))
            return cur.fetchall()
    finally:
        conn.close()

@app.get("/api/invoices/{invoice_id}")
def get_invoice(invoice_id: int):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            sql_inv = """
                SELECT i.id, i.invoice_number, i.customer_id, c.name as customer_name, c.email as customer_email,
                       CAST(i.total_amount AS DOUBLE) as total_amount, i.created_at
                FROM invoices i
                JOIN customers c ON i.customer_id = c.id
                WHERE i.id = %s
            """
            cur.execute(sql_inv, (invoice_id,))
            inv = cur.fetchone()
            if not inv:
                raise HTTPException(status_code=404, detail="Invoice not found")

            sql_items = """
                SELECT it.id, it.product_id, p.sku, p.name as product_name,
                       it.quantity, CAST(it.unit_price AS DOUBLE) as unit_price,
                       CAST(it.line_total AS DOUBLE) as line_total
                FROM invoice_items it
                JOIN products p ON it.product_id = p.id
                WHERE it.invoice_id = %s
            """
            cur.execute(sql_items, (invoice_id,))
            inv["items"] = cur.fetchall()
            return inv
    finally:
        conn.close()

@app.post("/api/invoices", status_code=status.HTTP_201_CREATED)
def create_invoice(payload: InvoiceCreate):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            # 1. Verify customer
            cur.execute("SELECT id, name FROM customers WHERE id = %s", (payload.customer_id,))
            customer = cur.fetchone()
            if not customer:
                raise HTTPException(status_code=400, detail="Customer ID not found")

            if not payload.items:
                raise HTTPException(status_code=400, detail="Invoice must contain at least one item")

            # 2. Verify all products and check stock
            total_amount = 0.0
            prepared_items = []
            for item in payload.items:
                cur.execute("SELECT id, sku, name, price, stock FROM products WHERE sku = %s FOR UPDATE", (item.product_sku,))
                prod = cur.fetchone()
                if not prod:
                    conn.rollback()
                    raise HTTPException(status_code=404, detail=f"Product with SKU '{item.product_sku}' not found")
                if prod["stock"] < item.quantity:
                    conn.rollback()
                    raise HTTPException(
                        status_code=400,
                        detail=f"Insufficient inventory for {prod['name']} (SKU: {prod['sku']}). Requested: {item.quantity}, Available: {prod['stock']}"
                    )
                # Server-side business logic validation: detect and reject price tampering
                catalog_price = float(prod["price"])
                if item.unit_price is not None and abs(item.unit_price - catalog_price) > 0.01:
                    conn.rollback()
                    raise HTTPException(
                        status_code=400,
                        detail=f"Price manipulation rejected: Client submitted unit_price ${item.unit_price:.2f} does not match catalog price ${catalog_price:.2f} for SKU '{item.product_sku}'."
                    )
                line_total = catalog_price * item.quantity
                total_amount += line_total
                prepared_items.append({
                    "product_id": prod["id"],
                    "sku": prod["sku"],
                    "quantity": item.quantity,
                    "unit_price": catalog_price,
                    "line_total": line_total
                })

            # 3. Create invoice header
            inv_number = f"INV-2026-{int(time.time() * 1000) % 1000000:06d}"
            cur.execute(
                "INSERT INTO invoices (invoice_number, customer_id, total_amount) VALUES (%s, %s, %s)",
                (inv_number, payload.customer_id, total_amount)
            )
            invoice_id = cur.lastrowid

            # 4. Insert line items and decrement stock
            for p in prepared_items:
                cur.execute(
                    "INSERT INTO invoice_items (invoice_id, product_id, quantity, unit_price, line_total) VALUES (%s, %s, %s, %s, %s)",
                    (invoice_id, p["product_id"], p["quantity"], p["unit_price"], p["line_total"])
                )
                cur.execute(
                    "UPDATE products SET stock = stock - %s WHERE id = %s",
                    (p["quantity"], p["product_id"])
                )

            # 5. Commit atomic transaction
            conn.commit()

            return {
                "success": True,
                "invoice_id": invoice_id,
                "invoice_number": inv_number,
                "customer": customer["name"],
                "total_amount": round(total_amount, 2),
                "items_count": len(prepared_items)
            }
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Transaction failed: {e}")
    finally:
        conn.close()

@app.get("/api/reports/daily-sales")
def daily_sales_report():
    conn = get_db()
    try:
        with conn.cursor() as cur:
            sql = """
                SELECT DATE(created_at) as sale_date,
                       COUNT(id) as total_invoices,
                       CAST(SUM(total_amount) AS DOUBLE) as total_revenue
                FROM invoices
                GROUP BY DATE(created_at)
                ORDER BY sale_date DESC LIMIT 14
            """
            cur.execute(sql)
            rows = cur.fetchall()
            for r in rows:
                if r.get("sale_date"):
                    r["sale_date"] = str(r["sale_date"])
            return rows
    finally:
        conn.close()
