"""Tests for Log Sentinel."""

from datetime import datetime, timedelta

import pytest

from src.main import (
    LogEvent,
    parse_auth_log_line,
    parse_log_file,
    detect_brute_force,
    detect_sudo_abuse,
    filter_by_severity,
    format_alerts_json,
)


class TestParseAuthLogLine:
    def test_valid_auth_failure_line(self):
        line = "Jan 15 10:23:41 server sshd[1234]: Failed password for admin from 192.168.1.50 port 54321 ssh2"
        event = parse_auth_log_line(line, year=2026)
        assert event is not None
        assert event.source_ip == "192.168.1.50"
        assert event.user == "admin"
        assert event.event_type == "auth_failure"

    def test_valid_sudo_line(self):
        line = "Jan 15 10:24:10 server sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
        event = parse_auth_log_line(line, year=2026)
        assert event is not None
        assert event.user == "alice"
        assert event.event_type == "sudo_command"

    def test_unmatched_line_returns_none(self):
        line = "This is not a log line at all"
        assert parse_auth_log_line(line, year=2026) is None


class TestParseLogFile:
    def test_parses_all_lines_in_sample_file(self, tmp_path):
        log_file = tmp_path / "auth.log"
        log_file.write_text(
            "Jan 15 10:23:41 server sshd[1234]: Failed password for admin from 192.168.1.50 port 54321 ssh2\n"
            "Jan 15 10:24:10 server sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash\n"
        )
        events = parse_log_file(str(log_file), "auth")
        assert len(events) == 2

    def test_empty_file_returns_empty_list(self, tmp_path):
        log_file = tmp_path / "empty.log"
        log_file.write_text("")
        events = parse_log_file(str(log_file), "auth")
        assert events == []

    def test_malformed_lines_are_skipped(self, tmp_path):
        log_file = tmp_path / "mixed.log"
        log_file.write_text(
            "not a real log line\n"
            "Jan 15 10:23:41 server sshd[1234]: Failed password for admin from 192.168.1.50 port 54321 ssh2\n"
        )
        events = parse_log_file(str(log_file), "auth")
        assert len(events) == 1

    def test_unimplemented_format_raises(self, tmp_path):
        log_file = tmp_path / "x.log"
        log_file.write_text("some line\n")
        with pytest.raises(NotImplementedError):
            parse_log_file(str(log_file), "made_up_format")


class TestDetectBruteForce:
    def make_event(self, ip, ts):
        return LogEvent(timestamp=ts, source_ip=ip, message="test", event_type="auth_failure", user="x")

    def test_five_failures_in_30s_triggers(self):
        base = datetime(2026, 1, 15, 10, 0, 0)
        events = [self.make_event("1.2.3.4", base + timedelta(seconds=i * 5)) for i in range(5)]
        alerts = detect_brute_force(events, threshold=5, window_seconds=60)
        assert len(alerts) == 1
        assert alerts[0].source_ip == "1.2.3.4"

    def test_four_failures_does_not_trigger(self):
        base = datetime(2026, 1, 15, 10, 0, 0)
        events = [self.make_event("1.2.3.4", base + timedelta(seconds=i * 5)) for i in range(4)]
        alerts = detect_brute_force(events, threshold=5, window_seconds=60)
        assert len(alerts) == 0

    def test_failures_spread_outside_window_does_not_trigger(self):
        base = datetime(2026, 1, 15, 10, 0, 0)
        events = [self.make_event("1.2.3.4", base + timedelta(minutes=i * 10)) for i in range(5)]
        alerts = detect_brute_force(events, threshold=5, window_seconds=60)
        assert len(alerts) == 0

    def test_two_ips_with_three_failures_each_does_not_trigger(self):
        base = datetime(2026, 1, 15, 10, 0, 0)
        events = (
            [self.make_event("1.1.1.1", base + timedelta(seconds=i * 5)) for i in range(3)]
            + [self.make_event("2.2.2.2", base + timedelta(seconds=i * 5)) for i in range(3)]
        )
        alerts = detect_brute_force(events, threshold=5, window_seconds=60)
        assert len(alerts) == 0


class TestDetectSudoAbuse:
    def make_sudo_event(self, user, ts=None):
        ts = ts or datetime(2026, 1, 15, 10, 0, 0)
        return LogEvent(timestamp=ts, message="sudo test", event_type="sudo_command", user=user)

    def test_unexpected_user_triggers_alert(self):
        events = [self.make_sudo_event("mallory")]
        alerts = detect_sudo_abuse(events, expected_sudoers=["alice", "root"])
        assert len(alerts) == 1
        assert alerts[0].user == "mallory"

    def test_expected_user_does_not_trigger(self):
        events = [self.make_sudo_event("alice")]
        alerts = detect_sudo_abuse(events, expected_sudoers=["alice", "root"])
        assert len(alerts) == 0


class TestFilterBySeverity:
    def test_high_excludes_low_and_medium(self):
        from src.main import Alert
        alerts = [
            Alert(alert_type="a", severity="low", message="m"),
            Alert(alert_type="a", severity="medium", message="m"),
            Alert(alert_type="a", severity="high", message="m"),
        ]
        filtered = filter_by_severity(alerts, "high")
        assert len(filtered) == 1
        assert filtered[0].severity == "high"

    def test_low_includes_all(self):
        from src.main import Alert
        alerts = [
            Alert(alert_type="a", severity="low", message="m"),
            Alert(alert_type="a", severity="critical", message="m"),
        ]
        filtered = filter_by_severity(alerts, "low")
        assert len(filtered) == 2

    def test_empty_list_returns_empty(self):
        assert filter_by_severity([], "low") == []
