# Security Engineering Portfolio

Python command-line security tools, each implemented from a starter stub,
covered by a pytest suite, and verified by hand. Built through
[The Engineers Club](https://github.com/saedctl/theengineersclub)
mentorship curriculum (mentor: Saed F.), progressing tier by tier.

## Fundamentals

| Project | What it does | Tests |
|---------|--------------|-------|
| [01-hashcheck](fundamentals/01-hashcheck) | Computes and verifies SHA-256/MD5 file hashes using chunked reads | 6 |
| [02-permscan](fundamentals/02-permscan) | Audits filesystem permissions: world-readable, world-writable, SUID | 12 |
| [03-encoding](fundamentals/03-encoding) | Encodes, decodes and auto-detects Base64, hex, URL and ROT13 | 15 |
| [04-subnet](fundamentals/04-subnet) | CIDR subnet calculator and IP membership checks | 9 |
| [05-loginsim](fundamentals/05-loginsim) | Authentication simulator: bcrypt hashing, account lockout, login history | 13 |

## Entry

| Project | What it does | Tests |
|---------|--------------|-------|
| [01-log-sentinel](entry/01-log-sentinel) | Parses auth/syslog/nginx logs, detects brute force with a sliding time window and sudo abuse, emits JSON alerts | 16 |

Next up in this tier: `02-fim`, `03-cve-cli`, `04-portscan`, `05-passaudit`.
Mid and senior tiers will be added as they are completed.

## Running the projects

Each project is self-contained:

```bash
cd fundamentals/01-hashcheck
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 -m pytest tests -v
```

To run every suite at once: `./run_all_tests.sh`

## About

Built by Umar Gambari, security professional working toward security
engineering roles. Certifications: Security+, CySA+, SC-200, AZ-900,
Google Cloud Digital Leader, CCNA.
