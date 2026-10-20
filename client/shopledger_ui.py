#!/usr/bin/env python3
"""
ShopLedger Mode A Textual Terminal UI
Interactive Two-Tier Client connecting directly to MySQL 8.0 on port 3306
Runs with restricted client_user credentials.
"""

import os
import sys
import time
from datetime import datetime

import pymysql
from pymysql.cursors import DictCursor
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
    TabbedContent,
    TabPane,
)

DB_HOST = os.environ.get("DB_HOST", "10.0.3.10")
DB_PORT = int(os.environ.get("DB_PORT", 3306))
DB_USER = os.environ.get("DB_USER", "client_user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "client_secure_pass_456")
DB_NAME = os.environ.get("DB_NAME", "shopledger")

def get_db():
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

class ShopLedgerApp(App):
    CSS = """
    Screen {
        background: #0b0f19;
    }
    Header {
        background: #1e293b;
        color: #38bdf8;
    }
    TabbedContent {
        height: 100%;
    }
    DataTable {
        height: 100%;
        background: #0f172a;
    }
    .form-box {
        padding: 1 2;
        background: #1e293b;
        border: solid #334155;
        margin: 1 2;
    }
    .status-msg {
        color: #10b981;
        margin-top: 1;
    }
    .error-msg {
        color: #ef4444;
        margin-top: 1;
    }
    Button {
        margin-top: 1;
        background: #0284c7;
        color: #ffffff;
    }
    """

    TITLE = "ShopLedger v2 (Mode A: Two-Tier Direct DB)"
    SUB_TITLE = f"Connected as client_user @ {DB_HOST}:{DB_PORT}"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh_data", "Refresh Tables"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent():
            with TabPane("Products Catalog", id="tab-products"):
                yield DataTable(id="table-products")
            with TabPane("Create Invoice", id="tab-invoice"):
                with VerticalScroll(classes="form-box"):
                    yield Label("[bold cyan]Direct Billing Transaction (client_user)[/bold cyan]")
                    yield Label("Customer ID (1 - 20):")
                    yield Input(placeholder="e.g. 1", id="inv-cust-id", value="1")
                    yield Label("Product SKU:")
                    yield Input(placeholder="e.g. SKU-1001", id="inv-sku", value="SKU-1001")
                    yield Label("Quantity:")
                    yield Input(placeholder="e.g. 2", id="inv-qty", value="2")
                    yield Button("Execute Transaction", id="btn-create-invoice", variant="primary")
                    yield Static("", id="inv-result")
            with TabPane("Low Stock Alerts", id="tab-lowstock"):
                yield DataTable(id="table-lowstock")
            with TabPane("Daily Sales Report", id="tab-sales"):
                yield DataTable(id="table-sales")
        yield Footer()

    def on_mount(self) -> None:
        self.action_refresh_data()

    def action_refresh_data(self) -> None:
        try:
            conn = get_db()
        except Exception as e:
            self.notify(f"DB connection failed: {e}", severity="error")
            return

        try:
            with conn.cursor() as cur:
                # 1. Products
                tbl_p = self.query_one("#table-products", DataTable)
                tbl_p.clear(columns=True)
                tbl_p.add_columns("SKU", "Product Name", "Category", "Price ($)", "Stock")
                cur.execute("SELECT sku, name, category, CAST(price AS DOUBLE) as price, stock FROM products ORDER BY id ASC")
                for r in cur.fetchall():
                    tbl_p.add_row(r["sku"], r["name"], r["category"], f"${r['price']:.2f}", str(r["stock"]))

                # 2. Low Stock
                tbl_l = self.query_one("#table-lowstock", DataTable)
                tbl_l.clear(columns=True)
                tbl_l.add_columns("SKU", "Product Name", "Category", "Stock Level", "Status")
                cur.execute("SELECT sku, name, category, stock FROM products WHERE stock <= 10 ORDER BY stock ASC")
                for r in cur.fetchall():
                    status = "[bold red]CRITICAL[/bold red]" if r["stock"] <= 5 else "[bold yellow]LOW[/bold yellow]"
                    tbl_l.add_row(r["sku"], r["name"], r["category"], str(r["stock"]), status)

                # 3. Daily Sales
                tbl_s = self.query_one("#table-sales", DataTable)
                tbl_s.clear(columns=True)
                tbl_s.add_columns("Date", "Total Invoices", "Daily Revenue ($)")
                cur.execute("""
                    SELECT DATE(created_at) as sale_date, COUNT(id) as total_inv, CAST(SUM(total_amount) AS DOUBLE) as rev
                    FROM invoices GROUP BY DATE(created_at) ORDER BY sale_date DESC LIMIT 14
                """)
                for r in cur.fetchall():
                    tbl_s.add_row(str(r["sale_date"]), str(r["total_inv"]), f"${r['rev']:.2f}")

            self.notify("Database data synchronized", severity="information")
        except Exception as e:
            self.notify(f"Query error: {e}", severity="error")
        finally:
            conn.close()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-create-invoice":
            self.handle_create_invoice()

    def handle_create_invoice(self) -> None:
        cust_id_str = self.query_one("#inv-cust-id", Input).value.strip()
        sku = self.query_one("#inv-sku", Input).value.strip()
        qty_str = self.query_one("#inv-qty", Input).value.strip()
        result_box = self.query_one("#inv-result", Static)

        try:
            cust_id = int(cust_id_str)
            qty = int(qty_str)
            if qty <= 0:
                raise ValueError("Quantity must be positive.")
        except ValueError as ve:
            result_box.update(f"[red]Input error: {ve}[/red]")
            return

        try:
            conn = get_db()
        except Exception as e:
            result_box.update(f"[red]DB Connection error: {e}[/red]")
            return

        try:
            with conn.cursor() as cur:
                cur.execute("SELECT id, name FROM customers WHERE id = %s", (cust_id,))
                cust = cur.fetchone()
                if not cust:
                    result_box.update(f"[red]Customer ID {cust_id} not found.[/red]")
                    return

                cur.execute("SELECT id, sku, name, price, stock FROM products WHERE sku = %s FOR UPDATE", (sku,))
                prod = cur.fetchone()
                if not prod:
                    result_box.update(f"[red]Product SKU '{sku}' not found.[/red]")
                    return
                if prod["stock"] < qty:
                    result_box.update(f"[red]Insufficient inventory for {prod['name']}. Available: {prod['stock']}[/red]")
                    return

                unit_price = float(prod["price"])
                total = unit_price * qty
                inv_num = f"INV-TUI-{int(time.time() * 1000) % 1000000:06d}"

                cur.execute("INSERT INTO invoices (invoice_number, customer_id, total_amount) VALUES (%s, %s, %s)",
                            (inv_num, cust_id, total))
                inv_id = cur.lastrowid
                cur.execute("INSERT INTO invoice_items (invoice_id, product_id, quantity, unit_price, line_total) VALUES (%s, %s, %s, %s, %s)",
                            (inv_id, prod["id"], qty, unit_price, total))
                cur.execute("UPDATE products SET stock = stock - %s WHERE id = %s", (qty, prod["id"]))
                conn.commit()

                result_box.update(
                    f"[green]✔ Success: Created {inv_num} for {cust['name']} | "
                    f"{qty}x {prod['name']} (${total:.2f}) | Remaining Stock: {prod['stock'] - qty}[/green]"
                )
                self.action_refresh_data()
        except Exception as e:
            conn.rollback()
            result_box.update(f"[red]Transaction failed: {e}[/red]")
        finally:
            conn.close()

if __name__ == "__main__":
    app = ShopLedgerApp()
    app.run()
