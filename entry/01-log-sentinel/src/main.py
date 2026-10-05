"""Log Sentinel — Log analysis and alerting for security operations."""

import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

import click
from pydantic import BaseModel


class LogEvent(BaseModel):
    timestamp: datetime
    source_ip: Optional[str] = None
    message: str
    event_type: str
    user: Optional[str] = None


class Alert(BaseModel):
    alert_type: str
    severity: str
    source_ip: Optional[str] = None
    user: Optional[str] = None
    event_count: Optional[int] = None
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    message: str


AUTH_FAILED_PATTERN = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(\S+) from (\S+) port \d+"
)

SUDO_PATTERN = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sudo:\s+"
    r"(\S+)\s+:.*COMMAND=(.+)"
)

SYSLOG_PATTERN = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[]+)(?:\[\d+\])?:\s+(.+)"
)

NGINX_PATTERN = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)'
)


def parse_auth_log_line(line: str, year: int = None) -> Optional[LogEvent]:
    """Parse a single auth.log line into a LogEvent, or None if it doesn't match."""
    if year is None:
        year = datetime.now().year

    m = AUTH_FAILED_PATTERN.match(line)
    if m:
        ts_str, user, ip = m.groups()
        timestamp = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
        return LogEvent(
            timestamp=timestamp,
            source_ip=ip,
            message=line.strip(),
            event_type="auth_failure",
            user=user,
        )

    m = SUDO_PATTERN.match(line)
    if m:
        ts_str, user, command = m.groups()
        timestamp = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
        return LogEvent(
            timestamp=timestamp,
            message=line.strip(),
            event_type="sudo_command",
            user=user,
        )

    return None


def parse_syslog_line(line: str, year: int = None) -> Optional[LogEvent]:
    """Parse a single syslog line into a LogEvent."""
    if year is None:
        year = datetime.now().year

    m = SYSLOG_PATTERN.match(line)
    if not m:
        return None

    ts_str, hostname, process, message = m.groups()
    timestamp = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")

    return LogEvent(
        timestamp=timestamp,
        message=line.strip(),
        event_type="syslog_generic",
        user=process.strip(),
    )


def parse_nginx_line(line: str) -> Optional[LogEvent]:
    """Parse a single nginx combined-format access log line."""
    m = NGINX_PATTERN.match(line)
    if not m:
        return None

    ip, ts_str, method, path, status, size = m.groups()
    timestamp = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")

    return LogEvent(
        timestamp=timestamp,
        source_ip=ip,
        message=line.strip(),
        event_type=f"http_{status}",
        user=None,
    )


def parse_log_file(filepath: str, log_format: str) -> list:
    """Parse a log file into structured LogEvent objects."""
    parsers = {
        "auth": parse_auth_log_line,
        "syslog": parse_syslog_line,
        "nginx": parse_nginx_line,
    }
    if log_format not in parsers:
        raise NotImplementedError(f"Parser for '{log_format}' format not implemented")

    parser_fn = parsers[log_format]
    events = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            event = parser_fn(line)
            if event is not None:
                events.append(event)
    return events


def detect_brute_force(events: list, threshold: int = 5, window_seconds: int = 60) -> list:
    """Detect brute-force login attempts: N+ failures from the same IP within a time window."""
    failures_by_ip = defaultdict(list)
    for event in events:
        if event.event_type == "auth_failure" and event.source_ip:
            failures_by_ip[event.source_ip].append(event.timestamp)

    alerts = []
    for ip, timestamps in failures_by_ip.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            window_start = timestamps[i]
            window_end = window_start + timedelta(seconds=window_seconds)
            count_in_window = sum(1 for t in timestamps if window_start <= t <= window_end)
            if count_in_window >= threshold:
                alerts.append(Alert(
                    alert_type="brute_force",
                    severity="high",
                    source_ip=ip,
                    event_count=count_in_window,
                    window_start=window_start,
                    window_end=window_end,
                    message=f"{count_in_window} failed login attempts from {ip} within {window_seconds}s",
                ))
                break
    return alerts


def detect_sudo_abuse(events: list, expected_sudoers: list = None) -> list:
    """Detect suspicious sudo usage from unexpected users."""
    if expected_sudoers is None:
        expected_sudoers = ["alice", "root"]

    alerts = []
    for event in events:
        if event.event_type == "sudo_command" and event.user not in expected_sudoers:
            alerts.append(Alert(
                alert_type="sudo_abuse",
                severity="medium",
                user=event.user,
                message=f"Unexpected sudo usage by '{event.user}': {event.message}",
            ))
    return alerts


def filter_by_severity(alerts: list, min_severity: str) -> list:
    """Filter alerts to only include those at or above min_severity."""
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_rank = severity_order[min_severity]
    return [a for a in alerts if severity_order[a.severity] >= min_rank]


def format_alerts_json(alerts: list) -> str:
    """Format alerts as JSON output."""
    return json.dumps([alert.model_dump(mode="json") for alert in alerts], indent=2)


@click.command()
@click.option("--file", "filepath", required=True, help="Path to log file to analyse")
@click.option("--format", "log_format", required=True,
              type=click.Choice(["auth", "syslog", "nginx"]), help="Log format to parse")
@click.option("--severity", default="low",
              type=click.Choice(["low", "medium", "high", "critical"]),
              help="Minimum severity level to report")
def main(filepath, log_format, severity):
    """Parse security logs and detect suspicious patterns."""
    try:
        events = parse_log_file(filepath, log_format)
    except FileNotFoundError:
        click.echo(f"Error: file not found: {filepath}", err=True)
        sys.exit(1)
    except NotImplementedError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    click.echo(f"Parsed {len(events)} events from {filepath}", err=True)

    all_alerts = []
    all_alerts.extend(detect_brute_force(events))
    all_alerts.extend(detect_sudo_abuse(events))

    filtered_alerts = filter_by_severity(all_alerts, severity)

    click.echo(format_alerts_json(filtered_alerts))


if __name__ == "__main__":
    main()
