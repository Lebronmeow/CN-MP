"""
Application Tier (Tier 2) - Flask Backend Service
Handles authentication, business logic, RBAC, Student Portal API,
and communicates with Database Tier (Tier 3) on port 3306.
"""

import os
import sys
import time
from functools import wraps
from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

import db

# Base directories
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(BACKEND_DIR, ".."))

app = Flask(__name__, static_folder=ROOT_DIR)
app.secret_key = os.getenv("SECRET_KEY", "cn-mini-project-secret-key-secure-3-tier-2026")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Enable CORS for cross-origin local dev while allowing credentials
CORS(app, supports_credentials=True, origins=["*"])


# Initialize Database connection (MySQL with SQLite fallback)
with app.app_context():
    db.init_db()


def get_client_ip():
    """Retrieve originating client IP address through Nginx reverse proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "192.168.1.20"


def admin_required(f):
    """Decorator to enforce Admin Role-Based Access Control."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_role = session.get("role")
        if user_role != "admin":
            client_ip = get_client_ip()
            db.log_network_audit(
                client_ip=client_ip,
                tier_source="App (Flask)",
                tier_dest="App (Flask)",
                port=5000,
                action=f"RBAC_REJECT {request.method} {request.path}",
                decision="DENY",
                details=f"Unauthorized access attempt: role '{user_role}' requires 'admin'"
            )
            return jsonify({
                "error": "Forbidden: Administrator privileges required for this operation",
                "role_required": "admin",
                "current_role": user_role or "guest"
            }), 403
        return f(*args, **kwargs)
    return decorated_function


# ==========================================
# 1. AUTHENTICATION & SESSION ENDPOINTS
# ==========================================

@app.route("/api/auth/login", methods=["POST"])
def login():
    """Authenticate user with username and password."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    client_ip = get_client_ip()

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = db.query_db("SELECT * FROM users WHERE username = %s", (username,), one=True)

    if not user or not check_password_hash(user["password_hash"], password):
        db.log_network_audit(
            client_ip=client_ip,
            tier_source="Web (Nginx)",
            tier_dest="App (Flask)",
            port=5000,
            action=f"LOGIN_FAIL user='{username}'",
            decision="DENY",
            details="Invalid credentials supplied"
        )
        return jsonify({"error": "Invalid username or password"}), 401

    # Store user in session
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["full_name"] = user["full_name"]

    db.log_network_audit(
        client_ip=client_ip,
        tier_source="Web (Nginx)",
        tier_dest="App (Flask)",
        port=5000,
        action=f"LOGIN_SUCCESS user='{username}' role='{user['role']}'",
        decision="ALLOW",
        details="User authenticated successfully. Session cookie established."
    )

    return jsonify({
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "full_name": user["full_name"],
            "email": user["email"]
        }
    })


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    """Clear user session."""
    user = session.get("username", "anonymous")
    session.clear()
    return jsonify({"message": f"User '{user}' logged out successfully"})


@app.route("/api/auth/me", methods=["GET"])
def get_current_user():
    """Check current session status."""
    if "user_id" in session:
        return jsonify({
            "authenticated": True,
            "user": {
                "id": session.get("user_id"),
                "username": session.get("username"),
                "role": session.get("role"),
                "full_name": session.get("full_name")
            }
        })
    return jsonify({
        "authenticated": False,
        "user": {
            "role": "guest",
            "username": "guest",
            "full_name": "Guest Visitor"
        }
    })


# ==========================================
# 2. STUDENT INFORMATION SYSTEM CRUD APIS
# ==========================================

@app.route("/api/students", methods=["GET"])
def list_students():
    """List students with search, department filtering, and pagination/sort."""
    client_ip = get_client_ip()
    search = request.args.get("search", "").strip()
    department = request.args.get("department", "").strip()
    status = request.args.get("status", "").strip()

    sql = "SELECT id, roll_number, name, email, department, year, semester, gpa, attendance_pct, status, phone FROM students WHERE 1=1"
    params = []

    if search:
        sql += " AND (name LIKE %s OR roll_number LIKE %s OR email LIKE %s)"
        pattern = f"%{search}%"
        params.extend([pattern, pattern, pattern])

    if department and department != "All":
        sql += " AND department = %s"
        params.append(department)

    if status and status != "All":
        sql += " AND status = %s"
        params.append(status)

    sql += " ORDER BY id ASC"

    students = db.query_db(sql, params)

    db.log_network_audit(
        client_ip=client_ip,
        tier_source="App (Flask)",
        tier_dest="Data (MySQL)",
        port=3306,
        action="SQL_QUERY SELECT students",
        decision="ALLOW",
        details=f"Retrieved {len(students)} student records matching query"
    )

    return jsonify({
        "total": len(students),
        "students": students,
        "tier_transit": {
            "client_to_web": {"source": client_ip, "dest": "10.0.1.10", "port": 443, "protocol": "HTTPS"},
            "web_to_app": {"source": "10.0.1.10", "dest": "10.0.2.10", "port": 5000, "protocol": "TCP/HTTP"},
            "app_to_db": {"source": "10.0.2.10", "dest": "10.0.3.10", "port": 3306, "protocol": "TCP/MySQL"}
        }
    })


@app.route("/api/students/<int:student_id>", methods=["GET"])
def get_student(student_id):
    """Retrieve detailed student profile including enrolled courses and academic standing."""
    client_ip = get_client_ip()
    student = db.query_db("SELECT * FROM students WHERE id = %s", (student_id,), one=True)
    if not student:
        return jsonify({"error": f"Student with ID {student_id} not found"}), 404

    # Fetch course enrollments for student
    courses = db.query_db("""
        SELECT c.course_code, c.course_name, c.credits, c.instructor, e.grade, e.attendance_pct
        FROM enrollments e
        JOIN courses c ON e.course_id = c.id
        WHERE e.student_id = %s
    """, (student_id,))

    student["courses"] = courses

    db.log_network_audit(
        client_ip=client_ip,
        tier_source="App (Flask)",
        tier_dest="Data (MySQL)",
        port=3306,
        action=f"SQL_QUERY SELECT student {student_id}",
        decision="ALLOW",
        details=f"Fetched profile for {student['name']} ({student['roll_number']})"
    )

    return jsonify(student)


@app.route("/api/students", methods=["POST"])
@admin_required
def create_student():
    """Create a new student record (Administrator only)."""
    client_ip = get_client_ip()
    data = request.get_json(silent=True) or {}

    required = ["roll_number", "name", "email", "department"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Field '{field}' is required"}), 400

    roll_number = data["roll_number"].strip()
    name = data["name"].strip()
    email = data["email"].strip()
    department = data["department"].strip()
    year = int(data.get("year", 1))
    semester = int(data.get("semester", 1))
    gpa = float(data.get("gpa", 3.5))
    attendance_pct = float(data.get("attendance_pct", 95.0))
    status = data.get("status", "Active")
    phone = data.get("phone", "")

    # Check for existing duplicate roll number or email
    existing = db.query_db("SELECT id FROM students WHERE roll_number = %s OR email = %s", (roll_number, email), one=True)
    if existing:
        return jsonify({"error": f"Student with roll number '{roll_number}' or email '{email}' already exists"}), 409

    new_id, _ = db.execute_db("""
        INSERT INTO students (roll_number, name, email, department, year, semester, gpa, attendance_pct, status, phone)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (roll_number, name, email, department, year, semester, gpa, attendance_pct, status, phone))

    db.log_network_audit(
        client_ip=client_ip,
        tier_source="App (Flask)",
        tier_dest="Data (MySQL)",
        port=3306,
        action=f"SQL_INSERT student id={new_id}",
        decision="ALLOW",
        details=f"Admin added student record: {name} ({roll_number})"
    )

    return jsonify({
        "message": "Student created successfully",
        "student_id": new_id
    }), 201


@app.route("/api/students/<int:student_id>", methods=["PUT"])
@admin_required
def update_student(student_id):
    """Update student record (Administrator only)."""
    client_ip = get_client_ip()
    student = db.query_db("SELECT id FROM students WHERE id = %s", (student_id,), one=True)
    if not student:
        return jsonify({"error": "Student not found"}), 404

    data = request.get_json(silent=True) or {}
    fields = []
    params = []

    allowed_fields = ["name", "email", "department", "year", "semester", "gpa", "attendance_pct", "status", "phone"]
    for field in allowed_fields:
        if field in data:
            fields.append(f"{field} = %s")
            params.append(data[field])

    if not fields:
        return jsonify({"error": "No valid fields provided for update"}), 400

    params.append(student_id)
    sql = f"UPDATE students SET {', '.join(fields)} WHERE id = %s"
    db.execute_db(sql, params)

    db.log_network_audit(
        client_ip=client_ip,
        tier_source="App (Flask)",
        tier_dest="Data (MySQL)",
        port=3306,
        action=f"SQL_UPDATE student id={student_id}",
        decision="ALLOW",
        details=f"Admin updated fields: {', '.join(fields)}"
    )

    return jsonify({"message": "Student updated successfully", "student_id": student_id})


@app.route("/api/students/<int:student_id>", methods=["DELETE"])
@admin_required
def delete_student(student_id):
    """Delete a student record (Administrator only)."""
    client_ip = get_client_ip()
    student = db.query_db("SELECT roll_number, name FROM students WHERE id = %s", (student_id,), one=True)
    if not student:
        return jsonify({"error": "Student not found"}), 404

    db.execute_db("DELETE FROM students WHERE id = %s", (student_id,))

    db.log_network_audit(
        client_ip=client_ip,
        tier_source="App (Flask)",
        tier_dest="Data (MySQL)",
        port=3306,
        action=f"SQL_DELETE student id={student_id}",
        decision="ALLOW",
        details=f"Admin removed student {student['name']} ({student['roll_number']})"
    )

    return jsonify({"message": f"Student '{student['name']}' deleted successfully"})


# ==========================================
# 3. METRICS & OVERALL STATS
# ==========================================

@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Return dashboard summary metrics."""
    total_students = db.query_db("SELECT COUNT(*) as count FROM students", one=True)["count"]
    active_students = db.query_db("SELECT COUNT(*) as count FROM students WHERE status = 'Active'", one=True)["count"]
    avg_metrics = db.query_db("SELECT AVG(gpa) as avg_gpa, AVG(attendance_pct) as avg_att FROM students", one=True)

    departments = db.query_db("""
        SELECT department, COUNT(*) as count, ROUND(AVG(gpa), 2) as avg_gpa
        FROM students
        GROUP BY department
    """)

    return jsonify({
        "total_students": total_students,
        "active_students": active_students,
        "avg_gpa": round(avg_metrics["avg_gpa"] or 0.0, 2),
        "avg_attendance": round(avg_metrics["avg_att"] or 0.0, 1),
        "departments": departments
    })


# ==========================================
# 4. NETWORK SECURITY & ARCHITECTURE DEMO
# ==========================================

@app.route("/api/network/inspect", methods=["GET"])
def inspect_network_tiers():
    """Inspect the live 3-Tier architecture and return connection diagnostics for each tier."""
    client_ip = get_client_ip()
    web_tier_header = request.headers.get("X-Web-Tier", "Direct-Dev / Local Proxy")
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "http")

    db_status = db.get_db_status()

    tier_info = {
        "tier1_web": {
            "name": "Web Tier (Nginx Reverse Proxy)",
            "client_ip": client_ip,
            "ingress_port": 80 if forwarded_proto == "http" else 443,
            "protocol": forwarded_proto.upper(),
            "proxy_header": web_tier_header,
            "status": "HEALTHY",
            "role": "Accepts public HTTP/HTTPS client requests, applies security headers, proxies /api/ to App Tier"
        },
        "tier2_app": {
            "name": "Application Tier (Python Flask)",
            "host": "app:5000" if os.getenv("DOCKER_ENV") else "127.0.0.1:5000",
            "listen_port": 5000,
            "protocol": "TCP/HTTP",
            "status": "HEALTHY",
            "pid": os.getpid(),
            "python_version": sys.version.split()[0],
            "role": "Enforces authentication, RBAC, business logic, sanitizes input before querying Database"
        },
        "tier3_db": db_status
    }

    return jsonify(tier_info)


@app.route("/api/security/test-direct-db", methods=["POST"])
def test_direct_db_attack():
    """
    Simulates / tests an attack where a client attempts to bypass the Web Tier
    and Application Tier to connect directly to the MySQL database on port 3306.
    Demonstrates network firewall and Docker network isolation.
    """
    client_ip = get_client_ip()

    # Log the blocked direct attack attempt
    db.log_network_audit(
        client_ip=client_ip,
        tier_source="Client",
        tier_dest="Data (MySQL)",
        port=3306,
        action="DIRECT_DB_ACCESS_ATTEMPT",
        decision="DENY",
        details="Firewall Policy Check Failed: Client IP cannot directly access Database subnet (10.0.3.0/24 :3306). Connection dropped by Docker network isolation."
    )

    return jsonify({
        "success": False,
        "decision": "DENY",
        "badge": "BLOCKED BY FIREWALL",
        "attempted_path": {
            "source": f"Client ({client_ip})",
            "destination": "Database Tier (10.0.3.10:3306)",
            "port": 3306,
            "protocol": "TCP"
        },
        "firewall_rule_matched": "DENY client -> database :3306",
        "reason": "Direct client access to the database is forbidden. In our Docker network architecture, the database container resides exclusively on the private 'db_tier' network with no exposed host ports and no bridge to the public network.",
        "security_recommendation": "All queries must transit via Web Tier (Nginx :443) -> Application Tier (Flask :5000) -> Database Tier (MySQL :3306) under least privilege."
    })


@app.route("/api/security/audit-log", methods=["GET"])
def get_audit_logs():
    """Retrieve recent network firewall & access audit events."""
    limit = int(request.args.get("limit", 25))
    logs = db.query_db("SELECT * FROM network_audit_logs ORDER BY id DESC LIMIT %s", (limit,))
    return jsonify({"count": len(logs), "logs": logs})


# ==========================================
# 5. FRONTEND STATIC ASSETS SERVING
# ==========================================

@app.route("/")
def serve_index():
    """Serve the single-page application index.html."""
    return send_from_directory(ROOT_DIR, "index.html")


@app.route("/<path:path>")
def serve_static(path):
    """Serve static files (css, js, images, etc.)."""
    full_path = os.path.join(ROOT_DIR, path)
    if os.path.isfile(full_path):
        return send_from_directory(ROOT_DIR, path)
    return send_from_directory(ROOT_DIR, "index.html")


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"[*] Starting Application Tier (Flask) on port {port}...")
    app.run(host="0.0.0.0", port=port, debug=True)
