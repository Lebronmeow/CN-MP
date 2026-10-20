#!/usr/bin/env python3
"""
secrets_scan.py
Scans both working directory and full Git commit history for exposed secrets,
credentials, and tokens.
"""

import os
import re
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PATTERNS = [
    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']+)["\']', "Hardcoded Password"),
    (r'(?i)(?:api_key|apikey|secret_key)\s*[:=]\s*["\']([^"\']+)["\']', "API/Secret Key"),
    (r'(?i)(?:token|auth_token)\s*[:=]\s*["\']([^"\']+)["\']', "Auth Token"),
    (r'-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----', "Private Cryptographic Key"),
    (r'(?i)AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?i)ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token"),
]

EXCLUDE_EXTS = {".png", ".jpg", ".jpeg", ".pcap", ".pcap0", ".ico", ".svg"}
EXCLUDE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}

def scan_working_tree():
    print("=== Scanning Working Tree ===")
    findings = []
    for root, dirs, files in os.walk(BASE_DIR):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            if f == ".env":
                continue # .env is meant to store secrets and is gitignored
            ext = os.path.splitext(f)[1]
            if ext in EXCLUDE_EXTS:
                continue
            path = os.path.join(root, f)
            rel_path = os.path.relpath(path, BASE_DIR)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fp:
                    content = fp.read()
                    for pattern, label in PATTERNS:
                        for m in re.finditer(pattern, content):
                            snippet = m.group(0).strip()
                            line_num = content[:m.start()].count("\n") + 1
                            findings.append((rel_path, line_num, label, snippet))
            except Exception as e:
                pass
    return findings

def scan_git_history():
    print("\n=== Scanning Full Git History ===")
    findings = []
    res = subprocess.run(["git", "log", "-p", "--all"], capture_output=True, text=True, errors="ignore")
    current_commit = "UNKNOWN"
    current_file = "UNKNOWN"
    
    for line in res.stdout.splitlines():
        if line.startswith("commit "):
            current_commit = line.split()[1][:8]
        elif line.startswith("diff --git a/"):
            parts = line.split()
            if len(parts) >= 3:
                current_file = parts[2][2:]
        elif line.startswith("+") and not line.startswith("+++"):
            added = line[1:].strip()
            for pattern, label in PATTERNS:
                m = re.search(pattern, added)
                if m:
                    findings.append((current_commit, current_file, label, m.group(0)))
    return findings

def main():
    tree_findings = scan_working_tree()
    print(f"Working Tree findings: {len(tree_findings)}")
    for rel_path, line_num, label, snippet in tree_findings:
        print(f"  [{label}] {rel_path}:{line_num} -> {snippet[:60]}")

    hist_findings = scan_git_history()
    print(f"\nGit History findings: {len(hist_findings)}")
    for commit, file, label, snippet in hist_findings:
        print(f"  [{label}] ({commit}) {file} -> {snippet[:60]}")

if __name__ == "__main__":
    main()
