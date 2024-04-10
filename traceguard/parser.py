"""
Multi-format security log parser.
Directly implements Certiport Domain 3.5: Interpret System Logs
(Syslog, Auth logs, Web application logs, Windows audit events).
"""

import re
import json
from datetime import datetime, timezone
from typing import Optional, List, Iterator
from traceguard.models import LogEvent

# 1. Regex for Linux Auth.log SSH events
REGEX_SSH_FAILED = re.compile(
    r"(?P<date>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port\s+(?P<port>\d+)",
    re.IGNORECASE
)
REGEX_SSH_ACCEPTED = re.compile(
    r"(?P<date>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted (?:publickey|password) for (?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port\s+(?P<port>\d+)",
    re.IGNORECASE
)
REGEX_SUDO_EXEC = re.compile(
    r"(?P<date>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<cmd>.*)",
    re.IGNORECASE
)

# 2. Regex for Apache / Nginx Combined Log Format
REGEX_WEB_ACCESS = re.compile(
    r'^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+(?P<user>\S+)\s+\[(?P<date>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+[^"]+"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

# 3. Regex for Firewall / Port Scan drops (e.g. UFW / IPTables)
REGEX_FIREWALL_BLOCK = re.compile(
    r"(?P<date>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+.*\[(?:UFW BLOCK|IPTABLES_DROP)\]\s+.*SRC=(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+DST=(?P<dst_ip>\S+)\s+.*PROTO=(?P<proto>\w+)\s+.*DPT=(?P<port>\d+)"
)


def parse_syslog_timestamp(date_str: str) -> datetime:
    """Parse syslog date like 'Oct 29 14:22:01' assuming current year."""
    current_year = datetime.now(timezone.utc).year
    try:
        dt = datetime.strptime(f"{current_year} {date_str.strip()}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def parse_web_timestamp(date_str: str) -> datetime:
    """Parse web log date like '29/Oct/2026:14:22:01 +0000'."""
    try:
        # Strip timezone offset for simplified parsing
        clean_date = date_str.split()[0]
        dt = datetime.strptime(clean_date, "%d/%b/%Y:%H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def parse_log_line(line: str) -> Optional[LogEvent]:
    """
    Auto-detect log format and parse into a normalized LogEvent.
    Supports SSH auth.log, Apache/Nginx web access, firewall drops, and structured JSON.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # 1. Structured JSON Log format (e.g., Windows Event Forwarding or modern SIEM forwarders)
    if line.startswith("{") and line.endswith("}"):
        try:
            data = json.loads(line)
            ts_str = data.get("timestamp") or data.get("time") or ""
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                ts = datetime.now(timezone.utc)

            return LogEvent(
                timestamp=ts,
                log_type="json",
                source_ip=data.get("source_ip", data.get("ip", "unknown")),
                user=data.get("user", data.get("username", "unknown")),
                action=data.get("action", data.get("event", "unknown")),
                status=data.get("status", "unknown"),
                raw_message=line,
                details=data
            )
        except json.JSONDecodeError:
            pass

    # 2. SSH Failed Password (auth.log)
    m = REGEX_SSH_FAILED.search(line)
    if m:
        return LogEvent(
            timestamp=parse_syslog_timestamp(m.group("date")),
            log_type="auth",
            source_ip=m.group("ip"),
            user=m.group("user"),
            action="failed_login",
            status="failure",
            raw_message=line,
            details={"service": "sshd", "port": int(m.group("port"))}
        )

    # 3. SSH Accepted Login (auth.log)
    m = REGEX_SSH_ACCEPTED.search(line)
    if m:
        return LogEvent(
            timestamp=parse_syslog_timestamp(m.group("date")),
            log_type="auth",
            source_ip=m.group("ip"),
            user=m.group("user"),
            action="success_login",
            status="success",
            raw_message=line,
            details={"service": "sshd", "port": int(m.group("port"))}
        )

    # 4. Sudo Command Execution (auth.log)
    m = REGEX_SUDO_EXEC.search(line)
    if m:
        return LogEvent(
            timestamp=parse_syslog_timestamp(m.group("date")),
            log_type="auth",
            source_ip="127.0.0.1",
            user=m.group("user"),
            action="sudo_exec",
            status="success",
            raw_message=line,
            details={"command": m.group("cmd")}
        )

    # 5. Web Access Log (Apache / Nginx)
    m = REGEX_WEB_ACCESS.match(line)
    if m:
        path = m.group("path")
        status_code = int(m.group("status"))
        action = "web_request"
        status = "success" if status_code < 400 else "failure"

        # Check for web attack indicators in URI
        path_lower = path.lower()
        threat_tag = None
        if any(kw in path_lower for kw in ("..", "%2e%2e", "/etc/passwd", "win.ini", "boot.ini")):
            threat_tag = "path_traversal"
        elif any(kw in path_lower for kw in ("union select", "' or 1=1", "sleep(", "--", "select%20")):
            threat_tag = "sql_injection"
        elif any(kw in path_lower for kw in ("<script", "alert(", "javascript:", "onerror=")):
            threat_tag = "xss_probe"
        elif any(kw in path_lower for kw in ("/wp-admin", "/phpmyadmin", "/.env", "/.git", "/shell")):
            threat_tag = "sensitive_file_probe"

        return LogEvent(
            timestamp=parse_web_timestamp(m.group("date")),
            log_type="web",
            source_ip=m.group("ip"),
            user=m.group("user") if m.group("user") != "-" else "anonymous",
            action=action,
            status=status,
            raw_message=line,
            details={
                "method": m.group("method"),
                "path": path,
                "status_code": status_code,
                "user_agent": m.group("user_agent") or "",
                "threat_tag": threat_tag
            }
        )

    # 6. Firewall Block / Port Scan Detection
    m = REGEX_FIREWALL_BLOCK.search(line)
    if m:
        return LogEvent(
            timestamp=parse_syslog_timestamp(m.group("date")),
            log_type="firewall",
            source_ip=m.group("src_ip"),
            user="system",
            action="firewall_block",
            status="blocked",
            raw_message=line,
            details={
                "dst_ip": m.group("dst_ip"),
                "proto": m.group("proto"),
                "dst_port": int(m.group("port"))
            }
        )

    # Generic Syslog Fallback
    return LogEvent(
        timestamp=datetime.now(timezone.utc),
        log_type="syslog",
        source_ip="local",
        user="unknown",
        action="syslog_message",
        status="info",
        raw_message=line
    )


def parse_log_stream(lines: Iterator[str]) -> List[LogEvent]:
    """Parse an iterable sequence of log lines into LogEvent objects."""
    events = []
    for line in lines:
        ev = parse_log_line(line)
        if ev:
            events.append(ev)
    return events
