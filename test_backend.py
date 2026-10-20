"""
Unit Tests for Network Workbench 2.0 Backend & Policy Analyzer
Run with: python test_backend.py
"""

import unittest
import socket
import json
import time
from app import (
    check_target_safety,
    resolve_dns,
    probe_tcp_connection,
    PolicyAnalyzer,
    demo_controller,
    init_db,
    get_db_connection
)

class TestBackendDiagnostics(unittest.TestCase):

    def setUp(self):
        init_db()

    def test_safety_check_loopback_and_private(self):
        safe, cat, _ = check_target_safety("127.0.0.1")
        self.assertTrue(safe)
        self.assertEqual(cat, "LOCALHOST")

        safe, cat, _ = check_target_safety("localhost")
        self.assertTrue(safe)

        safe, cat, _ = check_target_safety("192.168.1.50")
        self.assertTrue(safe)
        self.assertEqual(cat, "PRIVATE_LAB")

        safe, cat, _ = check_target_safety("10.0.1.10")
        self.assertTrue(safe)
        self.assertEqual(cat, "PRIVATE_LAB")

    def test_safety_check_public_authorization(self):
        # Public IP without authorization should be rejected
        safe, cat, _ = check_target_safety("93.184.216.34", allow_public=False)
        self.assertFalse(safe)
        self.assertEqual(cat, "PUBLIC_RESTRICTED")

        # Public IP with authorization should be allowed
        safe, cat, _ = check_target_safety("93.184.216.34", allow_public=True)
        self.assertTrue(safe)
        self.assertEqual(cat, "PUBLIC_AUTHORIZED")

        # Safe diagnostic domain
        safe, cat, _ = check_target_safety("example.com", allow_public=False)
        self.assertTrue(safe)
        self.assertEqual(cat, "SAFE_PUBLIC")

    def test_dns_resolution(self):
        res = resolve_dns("localhost")
        self.assertTrue(res["success"])
        self.assertIn("127.0.0.1", res["ips"])
        self.assertGreaterEqual(res["latency_ms"], 0)

        # Invalid domain
        res_bad = resolve_dns("this-domain-does-not-exist-1234567.invalid")
        self.assertFalse(res_bad["success"])
        self.assertIn("DNS Resolution Error", res_bad["error"])

    def test_tcp_probe_reachable_and_refused(self):
        # Start demo server on 8080
        success, _ = demo_controller.start()
        self.assertTrue(success)
        time.sleep(0.1)

        # Probe port 8080 -> should be REACHABLE
        res_open = probe_tcp_connection("127.0.0.1", 8080, timeout=1.0)
        self.assertEqual(res_open["status"], "REACHABLE")
        self.assertEqual(res_open["code"], "OPEN")
        self.assertGreater(res_open["latency_ms"], 0)

        # Stop demo server
        demo_controller.stop()
        time.sleep(0.1)

        # Probe port 8080 again -> should be REFUSED (RST)
        res_closed = probe_tcp_connection("127.0.0.1", 8080, timeout=3.0)
        self.assertEqual(res_closed["status"], "UNREACHABLE")
        self.assertEqual(res_closed["code"], "REFUSED")
        self.assertIn("refused", res_closed["message"].lower())


class TestFirewallPolicyAnalyzer(unittest.TestCase):

    def test_detect_overly_broad_allow(self):
        rules = [
            {"id": "R-01", "source": "ANY", "destination": "ANY", "port": "*", "protocol": "TCP", "action": "ALLOW"},
            {"id": "R-02", "source": "ANY", "destination": "ANY", "port": "*", "protocol": "TCP", "action": "DENY"}
        ]
        analyzer = PolicyAnalyzer(rules)
        report = analyzer.analyze()
        findings = report["findings"]

        has_any_any = any(f["category"] == "UNRESTRICTED_ALLOW" for f in findings)
        self.assertTrue(has_any_any)

    def test_detect_sensitive_port_exposure(self):
        rules = [
            {"id": "R-01", "source": "0.0.0.0/0", "destination": "10.0.3.10", "port": "3306", "action": "ALLOW"},
            {"id": "R-02", "source": "ANY", "destination": "10.0.1.10", "port": "22", "action": "ALLOW"},
            {"id": "R-03", "source": "ANY", "destination": "ANY", "port": "*", "action": "DENY"}
        ]
        analyzer = PolicyAnalyzer(rules)
        report = analyzer.analyze()
        findings = report["findings"]

        sensitive_findings = [f for f in findings if f["category"] == "SENSITIVE_PORT_EXPOSURE"]
        self.assertGreaterEqual(len(sensitive_findings), 2)
        ports_flagged = [f["title"] for f in sensitive_findings]
        self.assertTrue(any("3306" in t for t in ports_flagged))
        self.assertTrue(any("22" in t for t in ports_flagged))

    def test_detect_shadowed_and_redundant_rules(self):
        rules = [
            # Rule 1 allows 10.0.0.0/8 on port 80
            {"id": "R-01", "source": "10.0.0.0/8", "destination": "10.0.1.10", "port": "80", "action": "ALLOW"},
            # Rule 2 denies a specific host 10.0.1.5 on port 80 -> SHADOWED by Rule 1!
            {"id": "R-02", "source": "10.0.1.5", "destination": "10.0.1.10", "port": "80", "action": "DENY"},
            # Rule 3 allows 10.0.1.6 on port 80 -> REDUNDANT because Rule 1 already allows 10.0.0.0/8!
            {"id": "R-03", "source": "10.0.1.6", "destination": "10.0.1.10", "port": "80", "action": "ALLOW"},
            # Catch-all
            {"id": "R-04", "source": "ANY", "destination": "ANY", "port": "*", "action": "DENY"}
        ]
        analyzer = PolicyAnalyzer(rules)
        report = analyzer.analyze()
        findings = report["findings"]

        shadowed = [f for f in findings if f["category"] == "SHADOWED_RULE"]
        self.assertTrue(any(f["rule_id"] == "R-02" for f in shadowed))

        redundant = [f for f in findings if f["category"] == "REDUNDANT_RULE"]
        self.assertTrue(any(f["rule_id"] == "R-03" for f in redundant))

    def test_detect_early_default_deny(self):
        rules = [
            {"id": "R-01", "source": "ANY", "destination": "ANY", "port": "*", "action": "DENY"},
            {"id": "R-02", "source": "client", "destination": "web", "port": "443", "action": "ALLOW"}
        ]
        analyzer = PolicyAnalyzer(rules)
        report = analyzer.analyze()
        findings = report["findings"]

        order_hazard = [f for f in findings if f["category"] == "ORDER_HAZARD"]
        self.assertEqual(len(order_hazard), 1)

    def test_detect_tier_bypass(self):
        rules = [
            {"id": "R-01", "source": "client", "destination": "database", "port": "3306", "action": "ALLOW"},
            {"id": "R-02", "source": "ANY", "destination": "ANY", "port": "*", "action": "DENY"}
        ]
        analyzer = PolicyAnalyzer(rules)
        report = analyzer.analyze()
        findings = report["findings"]

        bypass = [f for f in findings if f["category"] == "TIER_BYPASS"]
        self.assertEqual(len(bypass), 1)


if __name__ == "__main__":
    unittest.main()
