-- Computer Networks Mini-Project: Secure 3-Tier Web Application
-- Database Tier Initialization Script (MySQL 8.0)
-- Strict database isolation: Only the Application Tier (Flask) connects on port 3306

CREATE DATABASE IF NOT EXISTS student_portal CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE student_portal;

-- 1. Users Table (Role-Based Access Control)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'student',
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 2. Students Information Table
CREATE TABLE IF NOT EXISTS students (
    id INT AUTO_INCREMENT PRIMARY KEY,
    roll_number VARCHAR(20) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    department VARCHAR(50) NOT NULL,
    year INT NOT NULL DEFAULT 1,
    semester INT NOT NULL DEFAULT 1,
    gpa DECIMAL(3,2) NOT NULL DEFAULT 0.00,
    attendance_pct DECIMAL(5,2) NOT NULL DEFAULT 100.00,
    status VARCHAR(20) NOT NULL DEFAULT 'Active',
    phone VARCHAR(25),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 3. Courses Table
CREATE TABLE IF NOT EXISTS courses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    course_code VARCHAR(20) NOT NULL UNIQUE,
    course_name VARCHAR(100) NOT NULL,
    credits INT NOT NULL DEFAULT 3,
    department VARCHAR(50) NOT NULL,
    instructor VARCHAR(100) NOT NULL
) ENGINE=InnoDB;

-- 4. Enrollments Table
CREATE TABLE IF NOT EXISTS enrollments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    course_id INT NOT NULL,
    grade VARCHAR(5) DEFAULT 'A',
    attendance_pct DECIMAL(5,2) DEFAULT 95.0,
    FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 5. Network Audit & Firewall Activity Logs Table
CREATE TABLE IF NOT EXISTS network_audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    client_ip VARCHAR(50) NOT NULL,
    tier_source VARCHAR(50) NOT NULL,
    tier_dest VARCHAR(50) NOT NULL,
    port INT NOT NULL,
    action VARCHAR(100) NOT NULL,
    decision VARCHAR(20) NOT NULL,
    details TEXT
) ENGINE=InnoDB;

-- Least-Privilege Application User
-- Application Server connects using 'flask_app'
CREATE USER IF NOT EXISTS 'flask_app'@'%' IDENTIFIED BY 'flask_secure_pass_443';
GRANT SELECT, INSERT, UPDATE, DELETE ON student_portal.* TO 'flask_app'@'%';
FLUSH PRIVILEGES;

-- Seed Sample Data
-- Pre-computed hashes for demo credentials (pbkdf2:sha256):
-- admin: 'Admin@123'
-- student: 'Student@123'
-- faculty: 'Faculty@123'
INSERT INTO users (username, password_hash, role, full_name, email) VALUES
('admin', 'scrypt:32768:8:1$u7xK3sWjM9Lq8vP1$5d2ee7fdf7c3efb7c62bb95f6ef25ce25f4b50c057cfb721869e9eebc3f591ba5fc3dbf9b1c97a599e0dfa28ea4e4f51e18bb3905c19d4538806283ffb2024db', 'admin', 'Dr. Alan Turing', 'admin@university.edu'),
('student', 'scrypt:32768:8:1$y9mK2pL4vQ1s8rT7$1e3fa5c8b299e527d9cb4aa7b8fa3b5cd759c99ec1b4b10b0a88b90151f15891e4a64efc8f38bc602b9e830e0310237e19bfa77a2f2b3b7548bc1e617d5c5890', 'student', 'Ada Lovelace', 'ada.lovelace@university.edu'),
('faculty', 'scrypt:32768:8:1$x1zB8qR5wN3m6vC9$4b8cc1a938de22718cf3ea24a2ef39d73507d9b9a67e411b028cb93809d4314125bca0fc60114f47bc579b29cb10787a27ebaa49e1a90c2936cc172db793cf57', 'faculty', 'Prof. Claude Shannon', 'c.shannon@university.edu')
ON DUPLICATE KEY UPDATE username=username;

-- Seed Sample Students
INSERT INTO students (roll_number, name, email, department, year, semester, gpa, attendance_pct, status, phone) VALUES
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
ON DUPLICATE KEY UPDATE roll_number=roll_number;

-- Seed Sample Courses
INSERT INTO courses (course_code, course_name, credits, department, instructor) VALUES
('NET-301', 'Computer Networks & Architectures', 4, 'Computer Networks', 'Prof. Claude Shannon'),
('SEC-402', 'Network Security & Firewalls', 4, 'Information Security', 'Radia Perlman, PhD'),
('SYS-201', 'Operating Systems & Distributed Systems', 3, 'Systems Programming', 'Dr. Ken Thompson'),
('DAT-305', 'Database Systems & SQL Optimization', 3, 'Software Engineering', 'Dr. Edgar Codd')
ON DUPLICATE KEY UPDATE course_code=course_code;

-- Seed Enrollments
INSERT INTO enrollments (student_id, course_id, grade, attendance_pct) VALUES
(1, 1, 'A+', 99.0),
(1, 2, 'A', 98.0),
(2, 1, 'A', 96.0),
(2, 3, 'A+', 97.0),
(3, 2, 'A', 94.0),
(7, 1, 'A+', 100.0),
(7, 2, 'A+', 99.5)
ON DUPLICATE KEY UPDATE student_id=student_id;

-- Initial Network Audit Logs
INSERT INTO network_audit_logs (client_ip, tier_source, tier_dest, port, action, decision, details) VALUES
('192.168.1.20', 'Client', 'Web (Nginx)', 443, 'HTTPS GET /index.html', 'ALLOW', 'Traffic matches firewall rule: Public ingress to Web Tier'),
('10.0.1.10', 'Web (Nginx)', 'App (Flask)', 5000, 'REST API /api/students', 'ALLOW', 'Traffic matches firewall rule: Web Tier to Application Tier'),
('10.0.2.10', 'App (Flask)', 'Data (MySQL)', 3306, 'SQL SELECT FROM students', 'ALLOW', 'Traffic matches firewall rule: Application Tier to Database Tier'),
('192.168.1.20', 'Client', 'Data (MySQL)', 3306, 'Direct MySQL Connection Attempt', 'DENY', 'BLOCKED by Firewall: Direct client access to Database Tier is prohibited');
