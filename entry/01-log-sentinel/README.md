# Log Sentinel

A log analysis and alerting tool for security operations.

## What it is

Log Sentinel parses authentication logs, syslog, and nginx access logs to detect suspicious patterns like brute-force login attempts, privilege escalation via sudo, and anomalous access patterns. It uses a configurable threshold engine (X events within Y seconds) and outputs structured JSON alerts.

This is the kind of tool SOC analysts and incident responders build and use daily. Commercial SIEMs do this at scale, but understanding the fundamentals — pattern matching, time windowing, alert fatigue management — is what separates operators who use tools from engineers who build them.

## What you'll build

- Log parser supporting auth.log, syslog, and nginx combined format
- Pattern detection engine with configurable thresholds (count + time window)
- Brute-force detection (N failed logins from same source in T seconds)
- Sudo abuse detection (sudo commands from unexpected users)
- JSON-structured alert output with severity levels
- CLI interface with `--file`, `--format`, and `--severity` flags

## Skills developed

- Log parsing and regex extraction
- Time-series event correlation
- Threshold-based alerting logic
- CLI design with click
- Data validation with pydantic
- Writing testable detection logic

## How to run

```bash
cd projects/entry/01-log-sentinel
make install
python src/main.py --file /var/log/auth.log --format auth --severity medium
python src/main.py --file /var/log/syslog --format syslog
python src/main.py --file /var/log/nginx/access.log --format nginx --severity high
```

## Stretch goals

- Add a `--watch` mode that tails a live log file
- Implement rate-based alerting (spike detection vs. static threshold)
- Add GeoIP enrichment for source IPs
- Export alerts to a SQLite database for later querying
- Build a summary report showing top offenders by source IP
