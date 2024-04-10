# TraceGuard SIEM 🚨
### Lightweight Security Information & Event Management & Threat Detection Engine
> **Directly Aligned with Certiport IT Specialist: Cybersecurity Exam Objectives (Domains 1, 3, 5)**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Dependencies: Zero](https://img.shields.io/badge/dependencies-0%20(Standard%20Library)-success.svg)]()
[![Tests: 8 Passed](https://img.shields.io/badge/tests-8%2F8%20passed-brightgreen.svg)]()
[![Certiport Aligned](https://img.shields.io/badge/Certiport-IT%20Specialist-orange.svg)]()

**TraceGuard SIEM** is a lightweight, high-speed Security Information and Event Management (SIEM) log parser, threat detection engine, and incident response correlator written in pure Python with **zero external dependencies**.

Engineered directly around the **Certiport IT Specialist: Cybersecurity Certification Syllabus**, TraceGuard normalizes disparate raw log formats (Syslog, Linux Auth, Apache/Nginx Web, Windows JSON, and Firewall drops), maps suspicious telemetry to the **MITRE ATT&CK Matrix**, and generates actionable **NIST SP 800-61 incident response containment playbooks**.

---

## 📋 Certiport Exam Objectives Alignment

| Certiport Exam Objective | Syllabus Topic | TraceGuard SIEM Implementation |
| :--- | :--- | :--- |
| **Domain 1.2: Common Threats** | Malware, brute force, Denial of Service, insider threats, privilege escalation. | Correlates password guessing bursts, rapid port sweeps, directory traversal, and unauthorized `sudo` executions. |
| **Domain 3.5: Interpret System Logs** | Event Viewer, audit logs, syslog, identification of anomalies. | Ingests and normalizes multi-source raw logs (Syslog, `auth.log`, Nginx/Apache Combined, and Firewall drops). |
| **Domain 5.1: Monitor Security Events** | Role of SIEM and SOAR, identifying suspicious events as they occur. | Stateful event correlation, frequency-based rate windowing, and incident escalation queuing. |
| **Domain 5.2: Attack Attribution & Forensics** | Cyber Kill Chain, MITRE ATT&CK Matrix, TTPs, forensic artifacts. | Maps detected threats to MITRE ATT&CK techniques (`T1110`, `T1046`, `T1190`, `T1083`, `T1078`) and preserves raw evidence artifacts. |
| **Domain 5.3: Compliance Frameworks** | GDPR, HIPAA, PCI-DSS incident reporting requirements. | Automatically annotates security alerts with regulatory compliance notifications (e.g. GDPR 72h breach window, PCI-DSS 8.1.6 lockout). |
| **Domain 5.4: Cybersecurity Incident Response** | NIST SP 800-61 lifecycle (Preparation, Detection, Containment, Eradication, Recovery). | Generates complete step-by-step incident response playbooks and ready-to-run firewall containment commands. |

---

## ✨ Key Features

- **Zero External Dependencies:** Built 100% on standard Python 3 (`re`, `datetime`, `json`, `collections`, `dataclasses`, `argparse`).
- **Multi-Format Log Parser:**
  - Linux Authentication (`/var/log/auth.log`, SSH failed/accepted logins, `sudo` execution).
  - Web Server Access Logs (Apache/Nginx Combined Log Format with SQLi and traversal pattern matching).
  - Firewall & Kernel Drops (UFW / IPTables packet drop logs).
  - Modern Structured JSON telemetry.
- **MITRE ATT&CK Threat Correlation:**
  - **T1110 (Brute Force):** Detects automated credential stuffing and flags account compromise if followed by a successful login.
  - **T1046 (Network Service Discovery):** Identifies horizontal and vertical port sweeps.
  - **T1190 (Exploit Public-Facing Application):** Detects SQL injection attempts in HTTP queries.
  - **T1083 (File and Directory Discovery):** Intercepts path traversal probes (`../`, `/etc/passwd`).
  - **T1078 (Valid Accounts / Privilege Escalation):** Detects high-risk administrative shell spawning via `sudo`.
- **NIST SP 800-61 Automated Playbooks:**
  - Provides instant, copy-pasteable firewall containment commands (`iptables` and Windows `netsh`).
  - Clear checklists for Eradication, Recovery, and Post-Incident review.
- **Interactive HTML SOC Dashboard:** Generates an executive dark-themed SOC operations console featuring metrics, MITRE TTP tags, and incident queues.
- **Ready-to-Run Attack Scenario (`--demo`):** Built-in realistic multi-stage intrusion log (`logs/attack_scenario.log`).

---

## 🏗️ Architecture & Project Structure

```text
traceguard/
├── traceguard/
│   ├── __init__.py             # Package metadata
│   ├── models.py               # LogEvent, SecurityAlert, IncidentPlaybook dataclasses
│   ├── parser.py               # Multi-format log parser (Syslog, Auth, Web, Firewall)
│   ├── detector.py             # Correlation engine & MITRE ATT&CK mapper
│   ├── playbooks.py            # NIST SP 800-61 response playbooks & containment commands
│   ├── reporter.py             # CLI formatter, JSON exporter & HTML SOC dashboard
│   └── core.py                 # SIEM orchestrator
├── logs/
│   └── attack_scenario.log     # Realistic multi-stage attack scenario
├── reports/
│   ├── siem_soc_dashboard.html # Generated interactive SOC incident dashboard
│   └── siem_alerts.json        # Machine-readable incident feed
├── tests/
│   └── test_siem.py            # Unit test suite (8 test cases)
├── traceguard.py               # CLI entrypoint
├── requirements.txt            # Zero dependencies declaration
├── LICENSE                     # MIT License
└── README.md                   # Documentation
```

---

## 🚀 Quickstart & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/zubairkram/traceguard.git
cd traceguard
```

### 2. Verify Prerequisites
Requires **Python 3.8+**. No external packages needed!
```bash
python --version
```

### 3. Run the Attack Scenario Demo
Simulate an enterprise intrusion analysis in under a second:
```bash
python traceguard.py --demo
```
This processes the built-in attack log, outputs the SOC console feed, and generates `reports/siem_soc_dashboard.html`.

---

## 💻 Usage & CLI Examples

### Ingest Custom Server Log Files
```bash
python traceguard.py /var/log/auth.log
```

### Ingest Multiple Logs with Custom Alerts Output
```bash
python traceguard.py /var/log/auth.log /var/log/nginx/access.log --html reports/my_soc.html --json reports/my_alerts.json
```

### Fine-Tune Correlation Thresholds
```bash
# Trigger brute force alerts after 3 failures instead of 5
python traceguard.py auth.log --threshold-brute 3 --threshold-scan 2
```

---

## 📊 Sample Output

### Terminal SOC Summary
```text
==================== SIEM THREAT HUNTING REPORT ====================
Session:             Enterprise Intrusion & Cyber Kill Chain Simulation
Processed Events:    19 log entries in 0.006s
Total Alerts:        4 incident(s) flagged
Unique Threat Hosts: 3 source IP(s)
====================================================================

ACTIVE SECURITY INCIDENTS (Certiport Domain 5.1 & 5.2):
  [CRITICAL] Automated Credential Brute-Force Attack
    Alert ID:    TG-ALERT-0001 | Time: 2026-10-29 02:12:22 UTC
    Threat Host: 198.51.100.77 (Target: webuser) | Events: 7
    MITRE TTP:   T1110 (Brute Force: Password Guessing) - Tactic: Credential Access
    Details:     Detected 7 failed attempts targeting webuser. [!] CRITICAL: Followed by successful login!
    Containment: sudo iptables -A INPUT -s 198.51.100.77 -j DROP

  [HIGH] Directory Traversal / Arbitrary File Read
    Alert ID:    TG-ALERT-0003 | Time: 2026-10-29 02:15:22 UTC
    Threat Host: 198.51.100.88 (Target: www-data) | Events: 2
    MITRE TTP:   T1083 (File and Directory Discovery) - Tactic: Discovery
    Details:     Detected 2 directory traversal probes attempt to read sensitive system files.
    Containment: sudo iptables -A INPUT -s 198.51.100.88 -j DROP
...
[+] HTML SOC Incident Dashboard generated: reports/siem_soc_dashboard.html
```

---

## 🧪 Running Unit Tests

Run the test suite using Python's built-in test runner:

```bash
python -m unittest discover -s tests -v
```

Output:
```text
test_brute_force_detection (test_siem.TestTraceGuardDetector.test_brute_force_detection) ... ok
test_clean_traffic_no_alerts (test_siem.TestTraceGuardDetector.test_clean_traffic_no_alerts) ... ok
test_parse_firewall_block (test_siem.TestTraceGuardParser.test_parse_firewall_block) ... ok
test_parse_ssh_accepted (test_siem.TestTraceGuardParser.test_parse_ssh_accepted) ... ok
test_parse_ssh_failed (test_siem.TestTraceGuardParser.test_parse_ssh_failed) ... ok
test_parse_web_attack (test_siem.TestTraceGuardParser.test_parse_web_attack) ... ok
test_html_dashboard_generation (test_siem.TestTraceGuardReporting.test_html_dashboard_generation) ... ok
test_json_export (test_siem.TestTraceGuardReporting.test_json_export) ... ok

----------------------------------------------------------------------
Ran 8 tests in 0.031s

OK
```

---

## 🗺️ Certiport Cybersecurity Portfolio Roadmap

1. **Project 1: VigilScan** — Network Vulnerability Scanner & SSL/TLS Audit Engine *(Domains 1.4, 2.1, 2.2, 4.1, 4.2, 4.3)*
2. **Project 2 (This Repository): TraceGuard SIEM** — Lightweight Log Analyzer & MITRE ATT&CK Threat Detector *(Domains 1.2, 3.5, 5.1, 5.2, 5.3, 5.4)*
3. **Project 3: AuditArmor** — Endpoint Security & Host Hardening Compliance Auditor *(Domains 1.3, 3.1, 3.2, 3.3, 3.4)*
4. **Project 4: CryptoVault-CLI** — PKI, Data-at-Rest/Transit Encryption & File Integrity Verifier *(Domains 1.1, 1.4)*

---

## ⚖️ License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for more details.
