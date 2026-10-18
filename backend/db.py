"""
Database Access Layer for 3-Tier Web Application.
Handles connection pooling to MySQL (Database Tier, port 3306) with resilient
fallback to SQLite for standalone local testing.
"""

import os
import time
import sqlite3
import pymysql
import pymysql.cursors
from werkzeug.security import generate_password_hash, check_password_hash

MYSQL_HOST = os.getenv("MYSQL_HOST", "db")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
MYSQL_USER = os.getenv("MYSQL_USER", "flask_app")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "flask_secure_pass_443")
MYSQL_DB = os.getenv("MYSQL_DATABASE", "student_portal")

SQLITE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "student_portal.db")

_use_sqlite = False
_db_status_cache = {}


def test_mysql_connection():
    """Try connecting to MySQL database server."""
    # In standalone local mode on Windows, avoid 2-second DNS timeout on unresolvable Docker hostname 'db'
    if MYSQL_HOST == "db" and not os.getenv("DOCKER_ENV"):
        return False, "Standalone local mode: container 'db' not in Docker network"

    try:
        conn = pymysql.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DB,
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=1,
            read_timeout=2,
            write_timeout=2,
        )
        conn.close()
        return True, "Connected to MySQL 8.0 on port 3306"
    except Exception as e:
        return False, str(e)


def init_sqlite_db():
    """Initialize SQLite database with identical schema and seed data for local testing."""
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            roll_number TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            department TEXT NOT NULL,
            year INTEGER NOT NULL DEFAULT 1,
            semester INTEGER NOT NULL DEFAULT 1,
            gpa REAL NOT NULL DEFAULT 0.0,
            attendance_pct REAL NOT NULL DEFAULT 100.0,
            status TEXT NOT NULL DEFAULT 'Active',
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_code TEXT UNIQUE NOT NULL,
            course_name TEXT NOT NULL,
            credits INTEGER NOT NULL DEFAULT 3,
            department TEXT NOT NULL,
            instructor TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS enrollments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            grade TEXT DEFAULT 'A',
            attendance_pct REAL DEFAULT 95.0,
            FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
            FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS network_audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT NOT NULL,
            tier_source TEXT NOT NULL,
            tier_dest TEXT NOT NULL,
            port INTEGER NOT NULL,
            action TEXT NOT NULL,
            decision TEXT NOT NULL,
            details TEXT
        );
    """)

    # Seed users if empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        admin_hash = generate_password_hash("Admin@123")
        student_hash = generate_password_hash("Student@123")
        faculty_hash = generate_password_hash("Faculty@123")

        cursor.executemany("""
            INSERT INTO users (username, password_hash, role, full_name, email)
            VALUES (?, ?, ?, ?, ?)
        """, [
            ('admin', admin_hash, 'admin', 'Dr. Alan Turing', 'admin@university.edu'),
            ('student', student_hash, 'student', 'Ada Lovelace', 'ada.lovelace@university.edu'),
            ('faculty', faculty_hash, 'faculty', 'Prof. Claude Shannon', 'c.shannon@university.edu'),
        ])

    # Seed students if empty
    cursor.execute("SELECT COUNT(*) FROM students")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("""
            INSERT INTO students (roll_number, name, email, department, year, semester, gpa, attendance_pct, status, phone)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            ('CS2024-001', 'Ada Lovelace', 'ada.lovelace@university.edu', 'Computer Science', 3, 5, 3.98, 98.50, 'Active', '+1-555-0101'),
            ('CS2024-002', 'Grace Hopper', 'grace.hopper@university.edu', 'Computer Science', 4, 7, 3.95, 96.20, 'Active', '+1-555-0102'),
            ('CS2024-003', 'John von Neumann', 'john.vn@university.edu', 'Information Security', 3, 6, 3.89, 94.00, 'Active', '+1-555-0103'),
            ('CS2024-004', 'Margaret Hamilton', 'm.hamilton@university.edu', 'Software Engineering', 4, 8, 3.99, 99.10, 'Active', '+1-555-0104'),
            ('CS2024-005', 'Tim Berners-Lee', 'tim.bl@university.edu', 'Computer Networks', 3, 5, 3.82, 92.50, 'Active', '+1-555-0105'),
            ('CS2024-006', 'Vint Cerf', 'vint.cerf@university.edu', 'Computer Networks', 2, 4, 3.87, 95.00, 'Active', '+1-555-0106'),
            ('CS2024-007', 'Radia Perlman', 'radia.perlman@university.edu', 'Network Security', 3, 6, 3.94, 97.80, 'Active', '+1-555-0107'),
            ('CS2024-008', 'Linus Torvalds', 'linus.t@university.edu', 'Operating Systems', 4, 7, 3.91, 91.00, 'Active', '+1-555-0108'),
            ('CS2024-009', 'Donald Knuth', 'donald.knuth@university.edu', 'Algorithms & Data', 4, 8, 4.00, 99.50, 'Active', '+1-555-0109'),
            ('CS2024-010', 'Dennis Ritchie', 'dennis.r@university.edu', 'Systems Programming', 4, 8, 3.96, 96.00, 'Active', '+1-555-0110')
        ])

    # Seed courses if empty
    cursor.execute("SELECT COUNT(*) FROM courses")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("""
            INSERT INTO courses (course_code, course_name, credits, department, instructor)
            VALUES (?, ?, ?, ?, ?)
        """, [
            ('NET-301', 'Computer Networks & Architectures', 4, 'Computer Networks', 'Prof. Claude Shannon'),
            ('SEC-402', 'Network Security & Firewalls', 4, 'Information Security', 'Radia Perlman, PhD'),
            ('SYS-201', 'Operating Systems & Distributed Systems', 3, 'Systems Programming', 'Dr. Ken Thompson'),
            ('DAT-305', 'Database Systems & SQL Optimization', 3, 'Software Engineering', 'Dr. Edgar Codd')
        ])

    # Seed initial enrollments
    cursor.execute("SELECT COUNT(*) FROM enrollments")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("""
            INSERT INTO enrollments (student_id, course_id, grade, attendance_pct)
            VALUES (?, ?, ?, ?)
        """, [
            (1, 1, 'A+', 99.0),
            (1, 2, 'A', 98.0),
            (2, 1, 'A', 96.0),
            (2, 3, 'A+', 97.0),
            (3, 2, 'A', 94.0),
            (7, 1, 'A+', 100.0),
            (7, 2, 'A+', 99.5)
        ])

    # Initial Audit Logs
    cursor.execute("SELECT COUNT(*) FROM network_audit_logs")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("""
            INSERT INTO network_audit_logs (client_ip, tier_source, tier_dest, port, action, decision, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, [
            ('192.168.1.20', 'Client', 'Web (Nginx)', 443, 'HTTPS GET /index.html', 'ALLOW', 'Traffic matches firewall rule: Public ingress to Web Tier'),
            ('10.0.1.10', 'Web (Nginx)', 'App (Flask)', 5000, 'REST API /api/students', 'ALLOW', 'Traffic matches firewall rule: Web Tier to Application Tier'),
            ('10.0.2.10', 'App (Flask)', 'Data (MySQL)', 3306, 'SQL SELECT FROM students', 'ALLOW', 'Traffic matches firewall rule: Application Tier to Database Tier'),
            ('192.168.1.20', 'Client', 'Data (MySQL)', 3306, 'Direct MySQL Connection Attempt', 'DENY', 'BLOCKED by Firewall: Direct client access to Database Tier is prohibited')
        ])

    conn.commit()
    conn.close()


def init_db():
    """Detect whether to connect to MySQL or fall back to SQLite."""
    global _use_sqlite
    mysql_ok, msg = test_mysql_connection()
    if mysql_ok:
        _use_sqlite = False
        print(f"[Database Tier] Successfully connected to MySQL at {MYSQL_HOST}:{MYSQL_PORT}")
    else:
        _use_sqlite = True
        print(f"[Database Tier] MySQL unreachable ({msg}). Initializing local SQLite fallback at {SQLITE_PATH}")
        init_sqlite_db()


def get_db():
    """Returns database connection and dialect."""
    global _use_sqlite
    if not _use_sqlite:
        try:
            conn = pymysql.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DB,
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=True
            )
            return conn, "mysql"
        except Exception as e:
            # Dynamically fall back if MySQL drops
            print(f"[Database Tier Warning] MySQL connection failed ({e}). Falling back to SQLite.")
            _use_sqlite = True
            init_sqlite_db()

    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn, "sqlite"


def query_db(query, args=(), one=False):
    """Execute a read query and return dict or list of dicts."""
    start_time = time.time()
    conn, dialect = get_db()
    try:
        if dialect == "mysql":
            with conn.cursor() as cursor:
                cursor.execute(query, args)
                rows = cursor.fetchall()
                result = rows[0] if (one and rows) else (None if one else rows)
        else:
            # Replace %s with ? for SQLite syntax
            sqlite_query = query.replace("%s", "?")
            cursor = conn.cursor()
            cursor.execute(sqlite_query, args)
            rows = [dict(row) for row in cursor.fetchall()]
            result = rows[0] if (one and rows) else (None if one else rows)
            conn.close()
        return result
    finally:
        if dialect == "mysql":
            conn.close()


def execute_db(query, args=()):
    """Execute write query (INSERT, UPDATE, DELETE) and return lastrowid / affected rows."""
    conn, dialect = get_db()
    try:
        if dialect == "mysql":
            with conn.cursor() as cursor:
                cursor.execute(query, args)
                last_id = cursor.lastrowid
                rowcount = cursor.rowcount
            conn.close()
            return last_id, rowcount
        else:
            sqlite_query = query.replace("%s", "?")
            cursor = conn.cursor()
            cursor.execute(sqlite_query, args)
            last_id = cursor.lastrowid
            rowcount = cursor.rowcount
            conn.commit()
            conn.close()
            return last_id, rowcount
    except Exception as e:
        if dialect == "mysql":
            conn.close()
        raise e


def log_network_audit(client_ip, tier_source, tier_dest, port, action, decision, details=""):
    """Record packet checkpoint into network_audit_logs."""
    try:
        execute_db("""
            INSERT INTO network_audit_logs (client_ip, tier_source, tier_dest, port, action, decision, details)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (client_ip, tier_source, tier_dest, port, action, decision, details))
    except Exception as err:
        print(f"[Audit Log Error] Could not record network log: {err}")


def get_db_status():
    """Return live status, dialect, latency, and host of Database tier."""
    start = time.perf_counter()
    try:
        conn, dialect = get_db()
        if dialect == "mysql":
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
            conn.close()
            target_host = f"{MYSQL_HOST}:{MYSQL_PORT}"
        else:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            conn.close()
            target_host = "SQLite-Local (Fallback mode)"
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "status": "ONLINE",
            "tier": "Database Tier (Tier 3)",
            "dialect": dialect.upper(),
            "host": target_host,
            "port": 3306 if dialect == "mysql" else 0,
            "latency_ms": latency_ms,
            "isolated": True,
            "policy": "Restricted to App Tier (10.0.2.10/24) via Port 3306"
        }
    except Exception as e:
        return {
            "status": "OFFLINE",
            "tier": "Database Tier (Tier 3)",
            "error": str(e),
            "isolated": True
        }
