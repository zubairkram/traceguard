"""
SIEM Core Orchestrator.
Coordinates log ingestion, threat detection, correlation, and reporting.
"""

import time
from typing import List, Optional
from datetime import datetime, timezone

from traceguard.models import SiemReport, LogEvent
from traceguard.parser import parse_log_line
from traceguard.detector import ThreatDetector


def run_siem_analysis(
    log_sources: List[str],
    brute_force_threshold: int = 5,
    scan_threshold: int = 4,
    session_title: str = "SIEM Log Security Analysis"
) -> SiemReport:
    """
    Ingest lines from log file paths or strings, parse events, and detect threats.
    """
    start_time = time.perf_counter()
    all_events: List[LogEvent] = []

    for source in log_sources:
        try:
            with open(source, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    ev = parse_log_line(line)
                    if ev:
                        all_events.append(ev)
        except Exception as e:
            # Handle reading error gracefully
            pass

    # Run detection
    detector = ThreatDetector(
        brute_force_threshold=brute_force_threshold,
        scan_threshold=scan_threshold
    )
    alerts = detector.analyze_events(all_events)

    duration = round(time.perf_counter() - start_time, 3)

    # Unique source IPs seen
    seen_ips = {ev.source_ip for ev in all_events if ev.source_ip not in ("unknown", "local", "127.0.0.1")}

    # Build report
    report = SiemReport(
        session_title=session_title,
        run_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        total_logs_processed=len(all_events),
        duration_seconds=duration,
        alerts=alerts,
        source_ips_seen=len(seen_ips)
    )

    return report
