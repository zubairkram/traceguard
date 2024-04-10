"""
Threat detection and correlation engine.
Directly implements:
- Certiport Domain 5.1: Monitoring security events & anomaly detection
- Certiport Domain 5.2: MITRE ATT&CK Matrix mapping & Cyber Kill Chain
"""

from collections import defaultdict
from typing import List, Dict, Any, Tuple
from datetime import datetime, timedelta

from traceguard.models import LogEvent, SecurityAlert
from traceguard.playbooks import generate_playbook_for_attack


class ThreatDetector:
    """
    Stateful detection engine that correlates parsed LogEvents against
    detection signatures, thresholds, and MITRE ATT&CK techniques.
    """

    def __init__(self, brute_force_threshold: int = 5, scan_threshold: int = 4):
        self.brute_force_threshold = brute_force_threshold
        self.scan_threshold = scan_threshold

    def analyze_events(self, events: List[LogEvent]) -> List[SecurityAlert]:
        """
        Process a batch of normalized LogEvents and generate correlated SecurityAlerts.
        """
        alerts: List[SecurityAlert] = []
        alert_counter = 1

        # Aggregation buckets
        failed_logins_by_ip = defaultdict(list)
        firewall_blocks_by_ip = defaultdict(list)
        web_attacks_by_ip = defaultdict(list)
        sudo_events = []

        # 1. Bucket and inspect events
        for ev in events:
            # Failed logins (SSH, Windows, etc.)
            if ev.action == "failed_login":
                failed_logins_by_ip[ev.source_ip].append(ev)

            # Firewall blocks / port scans
            elif ev.action == "firewall_block":
                firewall_blocks_by_ip[ev.source_ip].append(ev)

            # Web application requests
            elif ev.log_type == "web":
                threat_tag = ev.details.get("threat_tag")
                if threat_tag:
                    web_attacks_by_ip[ev.source_ip].append(ev)

            # Sudo execution
            elif ev.action == "sudo_exec":
                sudo_events.append(ev)

        # 2. Rule: Credential Brute Force (MITRE T1110)
        for ip, ev_list in failed_logins_by_ip.items():
            if len(ev_list) >= self.brute_force_threshold:
                target_users = list({e.user for e in ev_list})
                primary_user = target_users[0] if target_users else "unknown"
                sample_msgs = [e.raw_message for e in ev_list[:3]]

                # Correlate if there was a subsequent successful login from the same IP (Compromise!)
                has_subsequent_success = any(
                    e.source_ip == ip and e.action == "success_login" for e in events
                )
                severity = "CRITICAL" if has_subsequent_success else "HIGH"
                desc = f"Detected {len(ev_list)} failed authentication attempts from IP {ip} targeting user(s) {', '.join(target_users)}."
                if has_subsequent_success:
                    desc += " [!] CRITICAL: Followed by a successful login! Account likely compromised."

                playbook = generate_playbook_for_attack("T1110", ip, primary_user)

                alerts.append(SecurityAlert(
                    alert_id=f"TG-ALERT-{alert_counter:04d}",
                    title="Automated Credential Brute-Force Attack",
                    severity=severity,
                    timestamp=ev_list[-1].timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    source_ip=ip,
                    target_user=primary_user,
                    event_count=len(ev_list),
                    mitre_tactic="Credential Access",
                    mitre_technique_id="T1110",
                    mitre_technique_name="Brute Force: Password Guessing",
                    description=desc,
                    evidence_samples=sample_msgs,
                    playbook=playbook
                ))
                alert_counter += 1

        # 3. Rule: Port Scan / Network Reconnaissance (MITRE T1046)
        for ip, ev_list in firewall_blocks_by_ip.items():
            # Check unique probed ports
            probed_ports = {e.details.get("dst_port") for e in ev_list if e.details.get("dst_port")}
            if len(probed_ports) >= self.scan_threshold or len(ev_list) >= self.scan_threshold:
                sample_msgs = [e.raw_message for e in ev_list[:3]]
                ports_str = ", ".join(str(p) for p in sorted(list(probed_ports))[:6])
                desc = f"Host {ip} performed horizontal/vertical port sweep across {len(probed_ports)} destination ports ({ports_str})."
                
                playbook = generate_playbook_for_attack("T1046", ip, "system")

                alerts.append(SecurityAlert(
                    alert_id=f"TG-ALERT-{alert_counter:04d}",
                    title="Network Service Discovery / Port Reconnaissance",
                    severity="MEDIUM",
                    timestamp=ev_list[-1].timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    source_ip=ip,
                    target_user="network",
                    event_count=len(ev_list),
                    mitre_tactic="Discovery",
                    mitre_technique_id="T1046",
                    mitre_technique_name="Network Service Discovery",
                    description=desc,
                    evidence_samples=sample_msgs,
                    playbook=playbook
                ))
                alert_counter += 1

        # 4. Rule: Web Application Exploit - SQLi / Directory Traversal (MITRE T1190 / T1083)
        for ip, ev_list in web_attacks_by_ip.items():
            traversal_count = sum(1 for e in ev_list if e.details.get("threat_tag") == "path_traversal")
            sqli_count = sum(1 for e in ev_list if e.details.get("threat_tag") == "sql_injection")
            probe_count = len(ev_list)

            if sqli_count > 0:
                playbook = generate_playbook_for_attack("T1190", ip, "web-app")
                alerts.append(SecurityAlert(
                    alert_id=f"TG-ALERT-{alert_counter:04d}",
                    title="SQL Injection Exploit Attempt",
                    severity="HIGH",
                    timestamp=ev_list[-1].timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    source_ip=ip,
                    target_user="www-data",
                    event_count=sqli_count,
                    mitre_tactic="Initial Access",
                    mitre_technique_id="T1190",
                    mitre_technique_name="Exploit Public-Facing Application",
                    description=f"Identified {sqli_count} SQL injection payloads targeting web endpoints from {ip}.",
                    evidence_samples=[e.raw_message for e in ev_list if e.details.get("threat_tag") == "sql_injection"][:3],
                    playbook=playbook
                ))
                alert_counter += 1

            if traversal_count > 0:
                playbook = generate_playbook_for_attack("T1083", ip, "web-app")
                alerts.append(SecurityAlert(
                    alert_id=f"TG-ALERT-{alert_counter:04d}",
                    title="Directory Traversal / Arbitrary File Read",
                    severity="HIGH",
                    timestamp=ev_list[-1].timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    source_ip=ip,
                    target_user="www-data",
                    event_count=traversal_count,
                    mitre_tactic="Discovery",
                    mitre_technique_id="T1083",
                    mitre_technique_name="File and Directory Discovery",
                    description=f"Detected {traversal_count} directory traversal probes attempt to read sensitive system files (e.g. /etc/passwd).",
                    evidence_samples=[e.raw_message for e in ev_list if e.details.get("threat_tag") == "path_traversal"][:3],
                    playbook=playbook
                ))
                alert_counter += 1

        # 5. Rule: High-Risk Sudo / Privilege Escalation (MITRE T1078)
        for ev in sudo_events:
            cmd = ev.details.get("command", "").lower()
            # Suspicious sudo executions
            if any(s in cmd for s in ("/bin/bash", "/bin/sh", "chmod 777", "visudo", "useradd", "chown")):
                playbook = generate_playbook_for_attack("T1078", "127.0.0.1", ev.user)
                alerts.append(SecurityAlert(
                    alert_id=f"TG-ALERT-{alert_counter:04d}",
                    title="Suspicious Administrative Privilege Escalation",
                    severity="HIGH",
                    timestamp=ev.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    source_ip="127.0.0.1",
                    target_user=ev.user,
                    event_count=1,
                    mitre_tactic="Privilege Escalation",
                    mitre_technique_id="T1078",
                    mitre_technique_name="Valid Accounts: Privilege Escalation",
                    description=f"User '{ev.user}' executed high-risk command via sudo: '{ev.details.get('command')}'.",
                    evidence_samples=[ev.raw_message],
                    playbook=playbook
                ))
                alert_counter += 1

        # Sort alerts by severity (CRITICAL first, then HIGH, MEDIUM, LOW)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        alerts.sort(key=lambda a: severity_order.get(a.severity, 4))

        return alerts
