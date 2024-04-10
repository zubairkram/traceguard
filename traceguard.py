#!/usr/bin/env python3
"""
TraceGuard SIEM - Lightweight Security Information & Event Management
CLI Entrypoint.
Aligned with Certiport IT Specialist: Cybersecurity Exam Objectives (Domains 1, 3, 5).
"""

import sys
import os
import argparse

# Add package directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from traceguard.core import run_siem_analysis
from traceguard.reporter import print_cli_banner, print_cli_summary, generate_html_dashboard, export_json, COLOR_CYAN, COLOR_RESET, COLOR_GREEN


def main():
    parser = argparse.ArgumentParser(
        description="TraceGuard SIEM - Threat Detection, Log Analytics & MITRE ATT&CK Correlator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python traceguard.py logs/attack_scenario.log
  python traceguard.py /var/log/auth.log --html reports/incident_dashboard.html
  python traceguard.py --demo
        """
    )

    parser.add_argument("log_files", nargs="*", help="Path(s) to log files (auth.log, access.log, syslog, json)")
    parser.add_argument("--demo", action="store_true", help="Run multi-stage attack scenario demonstration")
    parser.add_argument("--html", default="reports/siem_soc_dashboard.html", help="Path for HTML dashboard output")
    parser.add_argument("--json", default="reports/siem_alerts.json", help="Path for JSON incident output")
    parser.add_argument("--threshold-brute", type=int, default=5, help="Failed login threshold for brute force (default: 5)")
    parser.add_argument("--threshold-scan", type=int, default=4, help="Port scan threshold (default: 4)")
    parser.add_argument("--no-banner", action="store_true", help="Suppress ASCII header banner")

    args = parser.parse_args()

    if not args.no_banner:
        print_cli_banner()

    log_sources = args.log_files
    session_name = "Live Security Log Analysis"

    if args.demo or not log_sources:
        demo_log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "attack_scenario.log")
        if args.demo or (not log_sources and os.path.exists(demo_log)):
            print(f"{COLOR_CYAN}[DEMO MODE]{COLOR_RESET} Ingesting multi-stage enterprise attack scenario...")
            log_sources = [demo_log]
            session_name = "Enterprise Intrusion & Cyber Kill Chain Simulation"
        else:
            parser.print_help()
            sys.exit(1)

    # Execute analysis
    report = run_siem_analysis(
        log_sources=log_sources,
        brute_force_threshold=args.threshold_brute,
        scan_threshold=args.threshold_scan,
        session_title=session_name
    )

    # Render terminal output
    print_cli_summary(report)

    # Generate Reports
    if args.html:
        generate_html_dashboard(report, args.html)
        print(f"{COLOR_GREEN}[+] HTML SOC Incident Dashboard generated: {os.path.abspath(args.html)}{COLOR_RESET}")

    if args.json:
        export_json(report, args.json)
        print(f"{COLOR_GREEN}[+] Machine-readable Incident JSON saved: {os.path.abspath(args.json)}{COLOR_RESET}")


if __name__ == "__main__":
    main()
