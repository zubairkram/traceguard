"""
TraceGuard SIEM Reporting Engine.
Produces real-time terminal SOC feeds, structured JSON events,
and executive standalone HTML Incident Response Dashboards.
"""

import os
import sys
import json
from collections import Counter
from typing import Dict, Any, List
from traceguard.models import SiemReport, SecurityAlert

# Reconfigure stdout for UTF-8 on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Terminal ANSI Colors
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_CYAN = "\033[96m"
COLOR_GRAY = "\033[90m"


def print_cli_banner():
    """Print ASCII art banner for TraceGuard SIEM."""
    banner = f"""{COLOR_CYAN}{COLOR_BOLD}
  _______                  _____                     _ 
 |__   __|                / ____|                   | |
    | |_ __ __ _  ___ ___| |  __ _   _  __ _ _ __ __| |
    | | '__/ _` |/ __/ _ \\ | |_ | | | |/ _` | '__/ _` |
    | | | | (_| | (_|  __/ |__| | |_| | (_| | | | (_| |
    |_|_|  \\__,_|\\___\\___|\\_____|\\__,_|\\__,_|_|  \\__,_|
{COLOR_RESET}{COLOR_GRAY} Lightweight SIEM & Threat Detection Engine | Security Information & Event Management{COLOR_RESET}
"""
    print(banner)


def print_cli_summary(report: SiemReport):
    """Render a terminal SOC summary feed."""
    print(f"\n{COLOR_BOLD}==================== SIEM THREAT HUNTING REPORT ===================={COLOR_RESET}")
    print(f"Session:             {report.session_title}")
    print(f"Processed Events:    {report.total_logs_processed} log entries in {report.duration_seconds}s")
    print(f"Total Alerts:        {len(report.alerts)} incident(s) flagged")
    print(f"Unique Threat Hosts: {report.source_ips_seen} source IP(s)")
    print(f"{COLOR_BOLD}===================================================================={COLOR_RESET}\n")

    if not report.alerts:
        print(f"{COLOR_GREEN}[+] Clean Log Stream: Zero security threats or policy violations detected.{COLOR_RESET}\n")
        return

    print(f"{COLOR_BOLD}ACTIVE SECURITY INCIDENTS & THREAT ATTRIBUTIONS:{COLOR_RESET}")
    for a in report.alerts:
        sev_color = COLOR_RED if a.severity in ("CRITICAL", "HIGH") else (COLOR_YELLOW if a.severity == "MEDIUM" else COLOR_BLUE)
        print(f"  {sev_color}[{a.severity}]{COLOR_RESET} {COLOR_BOLD}{a.title}{COLOR_RESET}")
        print(f"    Alert ID:    {a.alert_id} | Time: {a.timestamp}")
        print(f"    Threat Host: {COLOR_CYAN}{a.source_ip}{COLOR_RESET} (Target: {a.target_user}) | Events: {a.event_count}")
        print(f"    MITRE TTP:   {COLOR_YELLOW}{a.mitre_technique_id} ({a.mitre_technique_name}){COLOR_RESET} - Tactic: {a.mitre_tactic}")
        print(f"    Details:     {a.description}")
        if a.playbook:
            print(f"    {COLOR_GREEN}Containment:{COLOR_RESET} {a.playbook.containment_command}")
        print()


def export_json(report: SiemReport, output_path: str):
    """Save SIEM report as structured JSON."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2)


def generate_html_dashboard(report: SiemReport, output_path: str):
    """
    Generate an executive SOC Incident Response Dashboard in standalone HTML.
    Includes MITRE ATT&CK matrix view, NIST SP 800-61 playbooks, and timeline.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    # Compute metric counts
    crit_count = sum(1 for a in report.alerts if a.severity == "CRITICAL")
    high_count = sum(1 for a in report.alerts if a.severity == "HIGH")
    med_count = sum(1 for a in report.alerts if a.severity == "MEDIUM")
    low_count = sum(1 for a in report.alerts if a.severity == "LOW")

    # Generate MITRE ATT&CK badges
    mitre_counts = Counter(f"{a.mitre_technique_id}: {a.mitre_technique_name}" for a in report.alerts)
    mitre_html = ""
    for tech, count in mitre_counts.items():
        mitre_html += f"""
        <div class="mitre-tag">
            <span class="mitre-id">{tech.split(':')[0]}</span>
            <span class="mitre-name">{tech.split(':')[1].strip()}</span>
            <span class="mitre-count">x{count}</span>
        </div>
        """
    if not mitre_html:
        mitre_html = "<span style='color: #94a3b8;'>No adversarial TTPs observed.</span>"

    # Generate Incident Cards
    alert_cards_html = ""
    for a in report.alerts:
        badge_class = f"badge-{a.severity.lower()}"
        playbook_html = ""
        if a.playbook:
            pb = a.playbook
            playbook_html = f"""
            <div class="playbook-box">
                <div class="pb-title">NIST SP 800-61 Incident Playbook: Containment & Eradication</div>
                <div class="cmd-box">
                    <code>{pb.containment_command}</code>
                </div>
                <div class="pb-grid">
                    <div>
                        <strong>Containment Actions:</strong>
                        <ul>
                            {''.join(f'<li>{act}</li>' for act in pb.containment_actions)}
                        </ul>
                    </div>
                    <div>
                        <strong>Eradication & Recovery:</strong>
                        <ul>
                            {''.join(f'<li>{act}</li>' for act in pb.eradication_steps)}
                        </ul>
                    </div>
                </div>
                <div class="compliance-tag">
                    <strong>Regulatory Impact:</strong> {pb.compliance_impact}
                </div>
            </div>
            """

        evidence_html = ""
        if a.evidence_samples:
            sample_lines = "\\n".join(a.evidence_samples[:3])
            evidence_html = f"""
            <div class="evidence-box">
                <div class="ev-title">Raw Log Evidence (Forensic Artifact):</div>
                <pre>{sample_lines}</pre>
            </div>
            """

        alert_cards_html += f"""
        <div class="alert-card">
            <div class="alert-top">
                <div style="display: flex; align-items: center; gap: 0.75rem;">
                    <span class="badge {badge_class}">{a.severity}</span>
                    <span class="alert-id">{a.alert_id}</span>
                    <h3 class="alert-title">{a.title}</h3>
                </div>
                <div class="alert-time">{a.timestamp}</div>
            </div>
            
            <div class="alert-meta-bar">
                <div><span>Attacker IP:</span> <strong>{a.source_ip}</strong></div>
                <div><span>Target Entity:</span> <strong>{a.target_user}</strong></div>
                <div><span>Events Correlated:</span> <strong>{a.event_count}</strong></div>
                <div><span>MITRE TTP:</span> <span class="tag-mitre">{a.mitre_technique_id} ({a.mitre_tactic})</span></div>
            </div>

            <p class="alert-desc">{a.description}</p>
            {evidence_html}
            {playbook_html}
        </div>
        """

    if not alert_cards_html:
        alert_cards_html = """
        <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px; padding: 2rem; text-align: center; color: #34d399;">
            <h3>✓ Security Baseline Maintained</h3>
            <p>All ingested logs conform to normal operational parameters. No threat signatures matched.</p>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TraceGuard SIEM - SOC Incident Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-base: #080c14;
            --bg-surface: #0f172a;
            --bg-card: #1e293b;
            --border: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --cyan: #06b6d4;
            --red: #ef4444;
            --amber: #f59e0b;
            --emerald: #10b981;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background-color: var(--bg-base);
            color: var(--text-primary);
            font-family: 'Inter', -apple-system, sans-serif;
            padding: 2rem 1rem;
        }}
        .container {{ max-width: 1160px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        .brand {{ display: flex; align-items: center; gap: 0.85rem; }}
        .brand-icon {{
            width: 44px; height: 44px;
            background: linear-gradient(135deg, #0284c7, #38bdf8);
            border-radius: 10px;
            display: flex; align-items: center; justify-content: center;
            font-weight: 800; font-size: 1.3rem; color: #fff;
            box-shadow: 0 0 16px rgba(56, 189, 248, 0.4);
        }}
        .brand h1 {{ font-size: 1.45rem; font-weight: 700; }}
        .brand p {{ font-size: 0.8rem; color: var(--text-secondary); }}
        .soc-meta {{ text-align: right; font-size: 0.85rem; color: var(--text-secondary); }}
        .soc-meta strong {{ color: var(--text-primary); }}

        /* Metric Grid */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1.25rem;
            margin-bottom: 2rem;
        }}
        @media (max-width: 768px) {{
            .metrics-grid {{ grid-template-columns: repeat(2, 1fr); }}
        }}
        .metric-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.25rem;
            display: flex; flex-direction: column;
        }}
        .metric-val {{ font-size: 2.1rem; font-weight: 800; line-height: 1.1; }}
        .metric-label {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-secondary); margin-top: 0.35rem; }}

        /* MITRE ATT&CK Matrix Panel */
        .card {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        .card-header {{
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            font-weight: 600;
            margin-bottom: 1rem;
        }}
        .mitre-tags-flex {{
            display: flex; flex-wrap: wrap; gap: 0.75rem;
        }}
        .mitre-tag {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0.4rem 0.75rem;
            display: flex; align-items: center; gap: 0.5rem;
            font-size: 0.85rem;
        }}
        .mitre-id {{ color: #38bdf8; font-family: 'JetBrains Mono', monospace; font-weight: 600; }}
        .mitre-count {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; border-radius: 4px; padding: 0.1rem 0.35rem; font-size: 0.75rem; font-weight: 700; }}

        /* Alert Cards */
        .alert-card {{
            background: var(--bg-card);
            border-left: 4px solid var(--border);
            border-radius: 0 10px 10px 0;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .alert-card:has(.badge-critical) {{ border-left-color: var(--red); }}
        .alert-card:has(.badge-high) {{ border-left-color: #f97316; }}
        .alert-card:has(.badge-medium) {{ border-left-color: var(--amber); }}
        .alert-card:has(.badge-low) {{ border-left-color: #3b82f6; }}

        .alert-top {{
            display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;
        }}
        .alert-title {{ font-size: 1.1rem; font-weight: 600; }}
        .alert-id {{ font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--text-secondary); }}
        .alert-time {{ font-size: 0.85rem; color: var(--text-secondary); }}

        .alert-meta-bar {{
            display: flex; flex-wrap: wrap; gap: 1.5rem;
            background: rgba(15, 23, 42, 0.6);
            padding: 0.6rem 1rem;
            border-radius: 6px;
            font-size: 0.85rem;
            margin-bottom: 0.85rem;
        }}
        .alert-meta-bar span {{ color: var(--text-secondary); }}
        .tag-mitre {{ color: #f59e0b; font-weight: 600; }}

        .alert-desc {{ font-size: 0.95rem; color: #cbd5e1; margin-bottom: 1rem; line-height: 1.5; }}

        /* Evidence */
        .evidence-box {{
            background: #090d16;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0.75rem 1rem;
            margin-bottom: 1rem;
        }}
        .ev-title {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-secondary); margin-bottom: 0.4rem; }}
        .evidence-box pre {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            color: #93c5fd;
            white-space: pre-wrap;
            word-break: break-all;
        }}

        /* Playbooks */
        .playbook-box {{
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid rgba(56, 189, 248, 0.3);
            border-radius: 8px;
            padding: 1rem 1.25rem;
        }}
        .pb-title {{ font-size: 0.85rem; font-weight: 700; color: #38bdf8; text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 0.5rem; }}
        .cmd-box {{
            background: #000;
            border-radius: 6px;
            padding: 0.6rem 0.85rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: #34d399;
            margin-bottom: 0.75rem;
            border: 1px solid #1e293b;
        }}
        .pb-grid {{
            display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; font-size: 0.85rem;
            margin-bottom: 0.75rem;
        }}
        @media (max-width: 650px) {{
            .pb-grid {{ grid-template-columns: 1fr; }}
        }}
        .pb-grid ul {{ margin-left: 1.2rem; margin-top: 0.25rem; color: #cbd5e1; }}
        .compliance-tag {{
            font-size: 0.8rem; color: #fde047; border-top: 1px solid rgba(51, 65, 85, 0.5); padding-top: 0.5rem;
        }}

        /* Badges */
        .badge {{
            display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px;
            font-size: 0.75rem; font-weight: 700; text-transform: uppercase;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }}
        .badge-medium {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
        .badge-low {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }}

        footer {{
            text-align: center; font-size: 0.8rem; color: var(--text-secondary);
            margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--border);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <div class="brand-icon">TG</div>
                <div>
                    <h1>TraceGuard SIEM Dashboard</h1>
                    <p>Security Information & Event Management & MITRE ATT&CK Correlator</p>
                </div>
            </div>
            <div class="soc-meta">
                <div>Session: <strong>{report.session_title}</strong></div>
                <div>Processed: <strong>{report.total_logs_processed} logs</strong> ({report.duration_seconds}s)</div>
                <div>Timestamp: <strong>{report.run_timestamp}</strong></div>
            </div>
        </header>

        <!-- Metric Grid -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-val" style="color: var(--red);">{crit_count}</div>
                <div class="metric-label">Critical Incidents</div>
            </div>
            <div class="metric-card">
                <div class="metric-val" style="color: #f97316;">{high_count}</div>
                <div class="metric-label">High Severity Alerts</div>
            </div>
            <div class="metric-card">
                <div class="metric-val" style="color: #38bdf8;">{report.source_ips_seen}</div>
                <div class="metric-label">Active Threat Hosts</div>
            </div>
            <div class="metric-card">
                <div class="metric-val" style="color: var(--emerald);">{report.total_logs_processed}</div>
                <div class="metric-label">Normalized Logs</div>
            </div>
        </div>

        <!-- MITRE ATT&CK Matrix Panel -->
        <div class="card">
            <div class="card-header">Observed Adversary Tactics & Techniques (MITRE ATT&CK Matrix)</div>
            <div class="mitre-tags-flex">
                {mitre_html}
            </div>
        </div>

        <!-- Incidents Feed -->
        <div class="card">
            <div class="card-header">Security Incident Queue & Automated Playbooks ({len(report.alerts)} Alerts)</div>
            {alert_cards_html}
        </div>

        <footer>
            TraceGuard SIEM v1.0.0 • Threat Intelligence & Automated Incident Response System.
        </footer>
    </div>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
