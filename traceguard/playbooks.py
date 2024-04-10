"""
NIST SP 800-61 Incident Response Playbooks & Compliance Triggers.
Directly implements Certiport Domain 5.4 (Incident Response Lifecycle)
and Domain 5.3 (Compliance Frameworks: GDPR, PCI-DSS, HIPAA).
"""

from typing import Dict, Any, List
from traceguard.models import IncidentPlaybook


def generate_playbook_for_attack(technique_id: str, attacker_ip: str, target_user: str) -> IncidentPlaybook:
    """
    Generate a tailored NIST SP 800-61 incident response playbook
    with exact containment commands and compliance obligations.
    """
    # Cross-platform containment commands
    linux_cmd = f"sudo iptables -A INPUT -s {attacker_ip} -j DROP"
    win_cmd = f'netsh advfirewall firewall add rule name="TraceGuard_Block_{attacker_ip}" dir=in action=block remoteip={attacker_ip}'
    combined_cmd = f"{linux_cmd}  # (Windows: {win_cmd})"

    if technique_id == "T1110":  # Brute Force
        return IncidentPlaybook(
            detection_summary=f"Automated credential brute-force attack detected from source {attacker_ip} targeting account '{target_user}'.",
            containment_actions=[
                f"Immediately block incoming connections from IP {attacker_ip} at network border firewall.",
                f"Temporarily lock or enforce password reset for targeted account '{target_user}'.",
                "Verify fail2ban or SSH rate-limiting policies are operating."
            ],
            containment_command=combined_cmd,
            eradication_steps=[
                "Inspect auth.log for any successful logins from this IP during the same timeframe.",
                "Revoke any active SSH sessions or OAuth tokens associated with the account.",
                "Enforce Multi-Factor Authentication (MFA) on all remote access endpoints."
            ],
            recovery_steps=[
                "Restore account access after user identity verification.",
                "Verify host integrity and review system process lists for unauthorized background daemons.",
                "Monitor auth logs for secondary attack waves."
            ],
            compliance_impact="PCI-DSS 8.1.6 (Account lockout after repeated attempts) & 10.2 (Audit log monitoring)."
        )

    elif technique_id == "T1190" or technique_id == "T1083":  # Web Exploit / Path Traversal
        return IncidentPlaybook(
            detection_summary=f"Web application exploit attempt (SQL Injection / Directory Traversal) originating from {attacker_ip}.",
            containment_actions=[
                f"Blacklist {attacker_ip} at the Web Application Firewall (WAF) or reverse proxy layer.",
                "Isolate affected web application instances from sensitive internal backend database segments.",
                "Capture live packet traces and preserve raw HTTP access logs for digital forensics."
            ],
            containment_command=combined_cmd,
            eradication_steps=[
                "Audit web server code and sanitize input parameters (apply prepared statements / parameterized queries).",
                "Verify web directory permissions to ensure read-only status for non-upload paths.",
                "Scan filesystem for newly dropped webshells or modified scripts."
            ],
            recovery_steps=[
                "Deploy patched application code to production.",
                "Conduct regression testing and automated vulnerability scan via VigilScan.",
                "Re-enable public web routing through WAF."
            ],
            compliance_impact="GDPR Article 33 (Assess potential personal data breach within 72 hours) & PCI-DSS 6.5 (Prevent common web vulnerabilities)."
        )

    elif technique_id == "T1046":  # Network Service Discovery / Port Scan
        return IncidentPlaybook(
            detection_summary=f"Reconnaissance port scanning activity detected from IP {attacker_ip}.",
            containment_actions=[
                f"Drop all traffic from reconnaissance host {attacker_ip}.",
                "Verify external firewall rules drop unsolicited SYN probes without responding with RST packets."
            ],
            containment_command=combined_cmd,
            eradication_steps=[
                "Audit perimeter network to verify no unneeded management ports are exposed.",
                "Check IDS/IPS signature databases to ensure automated blacklisting is synchronized."
            ],
            recovery_steps=[
                "Continue passive telemetry monitoring for correlation with subsequent exploit attempts.",
                "Log scanning source IP into threat intelligence sharing feed."
            ],
            compliance_impact="SOC 2 & ISO 27001 Perimeter Defense & Attack Surface Management controls."
        )

    elif technique_id == "T1078":  # Valid Accounts / Privilege Escalation
        return IncidentPlaybook(
            detection_summary=f"Unauthorized privilege escalation or off-hours sudo execution detected by user '{target_user}'.",
            containment_actions=[
                f"Suspend user account '{target_user}' immediately and terminate active shell sessions (`pkill -u {target_user}`).",
                "Freeze endpoint state or snapshot virtual machine to preserve volatile memory evidence."
            ],
            containment_command=f"sudo usermod -L {target_user} ; sudo pkill -u {target_user}",
            eradication_steps=[
                "Audit /etc/sudoers file for unauthorized NOPASSWD entries or modified permissions.",
                "Inspect user bash history (.bash_history) and recently modified files in /tmp and /var/tmp.",
                "Check cron jobs (`/etc/cron*`) and systemd services for persistence mechanisms."
            ],
            recovery_steps=[
                "Re-image compromised host if root compromise is confirmed.",
                "Re-issue all SSH keys and administrative credentials.",
                "Perform formal Post-Incident Review (Lessons Learned) within 5 business days."
            ],
            compliance_impact="HIPAA Security Rule 164.312 (Audit Controls) & GDPR Article 32 (Security of processing)."
        )

    # Generic Fallback Playbook
    return IncidentPlaybook(
        detection_summary=f"Security anomaly detected associated with source {attacker_ip}.",
        containment_actions=[f"Isolate host or block {attacker_ip} at network perimeter."],
        containment_command=combined_cmd,
        eradication_steps=["Investigate root cause and terminate rogue processes."],
        recovery_steps=["Restore validated operational state and monitor logs."],
        compliance_impact="General Security Baseline Monitoring."
    )
