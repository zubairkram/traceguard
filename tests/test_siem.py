"""
Unit test suite for TraceGuard SIEM.
Validates multi-format log parsing, threat correlation engine,
MITRE ATT&CK mapping, and reporting modules.
"""

import unittest
import os
import tempfile
import json
from datetime import datetime, timezone

from traceguard.parser import parse_log_line
from traceguard.models import LogEvent
from traceguard.detector import ThreatDetector
from traceguard.reporter import export_json, generate_html_dashboard
from traceguard.models import SiemReport


class TestTraceGuardParser(unittest.TestCase):
    def test_parse_ssh_failed(self):
        line = "Oct 29 10:15:20 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 55432 ssh2"
        event = parse_log_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.log_type, "auth")
        self.assertEqual(event.source_ip, "192.168.1.100")
        self.assertEqual(event.user, "admin")
        self.assertEqual(event.action, "failed_login")
        self.assertEqual(event.status, "failure")

    def test_parse_ssh_accepted(self):
        line = "Oct 29 10:15:30 server sshd[1234]: Accepted password for root from 192.168.1.100 port 55434 ssh2"
        event = parse_log_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.action, "success_login")
        self.assertEqual(event.user, "root")

    def test_parse_web_attack(self):
        line = '198.51.100.5 - - [29/Oct/2026:12:00:00 +0000] "GET /admin.php?id=1%20UNION%20SELECT%20null-- HTTP/1.1" 500 200 "-" "Mozilla"'
        event = parse_log_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.log_type, "web")
        self.assertEqual(event.source_ip, "198.51.100.5")
        self.assertEqual(event.details.get("threat_tag"), "sql_injection")

    def test_parse_firewall_block(self):
        line = "Oct 29 10:00:00 gw kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.1 DST=10.0.0.1 PROTO=TCP DPT=22"
        event = parse_log_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.log_type, "firewall")
        self.assertEqual(event.details.get("dst_port"), 22)


class TestTraceGuardDetector(unittest.TestCase):
    def test_brute_force_detection(self):
        detector = ThreatDetector(brute_force_threshold=3)
        events = [
            LogEvent(
                timestamp=datetime.now(timezone.utc),
                log_type="auth",
                source_ip="192.168.5.5",
                user="admin",
                action="failed_login",
                status="failure",
                raw_message="failed login"
            ) for _ in range(3)
        ]
        alerts = detector.analyze_events(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].mitre_technique_id, "T1110")
        self.assertEqual(alerts[0].source_ip, "192.168.5.5")

    def test_clean_traffic_no_alerts(self):
        detector = ThreatDetector()
        events = [
            LogEvent(
                timestamp=datetime.now(timezone.utc),
                log_type="web",
                source_ip="10.0.0.2",
                user="anonymous",
                action="web_request",
                status="success",
                raw_message="GET / HTTP/1.1"
            )
        ]
        alerts = detector.analyze_events(events)
        self.assertEqual(len(alerts), 0)


class TestTraceGuardReporting(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.report = SiemReport(
            session_title="Unit Test SIEM",
            total_logs_processed=100,
            duration_seconds=0.05,
            source_ips_seen=3
        )

    def test_json_export(self):
        path = os.path.join(self.test_dir, "siem_test.json")
        export_json(self.report, path)
        self.assertTrue(os.path.exists(path))
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["session_title"], "Unit Test SIEM")

    def test_html_dashboard_generation(self):
        path = os.path.join(self.test_dir, "dashboard_test.html")
        generate_html_dashboard(self.report, path)
        self.assertTrue(os.path.exists(path))
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("TraceGuard SIEM Dashboard", content)
        self.assertIn("Unit Test SIEM", content)


if __name__ == "__main__":
    unittest.main()
