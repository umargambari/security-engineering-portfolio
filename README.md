# Security Engineering Portfolio

A working portfolio of security tooling and cloud security projects,
built to demonstrate hands-on scripting, detection engineering, and AWS
security service experience.

## Repository layout

```
.
├── python-security-tools/
│   ├── hashcheck/    # File integrity verification (hashing, chunked reads)
│   ├── permscan/     # Filesystem permission auditing (stat, bitwise flags)
│   └── encoder/       # Multi-scheme encode/decode + auto-detection
└── aws-cloud-projects/
    ├── aws-detection-pipeline/   # GuardDuty -> EventBridge -> Lambda automation (case study)
    └── cloud-secops-platform/    # Phased SecOps build: landing zone + SIEM/SOAR (case study)
```

Each `python-security-tools/` project is fully self-contained: a working
CLI, a pytest test suite, and its own README with design notes. Run
`python3 -m pytest` inside any project folder to verify.

The `aws-cloud-projects/` folders are case-study summaries of larger
Terraform/Bicep builds that live in their own repos — see each README for
how to pull the full source in here.

## Quick start

```bash
git clone <this-repo-url>
cd security-engineering-portfolio
python3 -m venv venv && source venv/bin/activate
pip install pytest

# Run every test suite
python3 -m pytest python-security-tools -v
```

## Relevance to AWS Security Incident Response roles

| Requirement (from job postings) | Where it's demonstrated |
|---|---|
| Writing code/scripts to solve security problems | All three CLI tools — argparse-based, tested, documented |
| Web protocols & common security attacks | `encoder` — decoding obfuscated payloads/query params, auto-detection heuristics |
| System, network, and OS knowledge | `permscan` — OS-level permission internals via `stat`/bitwise checks |
| AWS services experience | `aws-detection-pipeline` — GuardDuty, EventBridge, Lambda, DynamoDB, SNS |
| Triaging alerts, automation, escalation | `cloud-secops-platform` Phase 2 — SIEM/SOAR playbook with automated enrichment and response |
| Infrastructure as code / secure CI/CD | Both AWS/cloud projects — Terraform/Bicep, GitHub OIDC (no static credentials) |

## Other projects

- **Host Triage Toolkit** — a modular Python CLI combining file-integrity
  monitoring, auth log anomaly detection, and secrets/IOC scanning. Kept
  as its own repo given its size.
- **defender-sentinel-soc** — the Azure-side SIEM/SOAR build referenced
  above (Sentinel KQL-as-code, Defender for Endpoint, Logic Apps).

See [github.com/umargambari](https://github.com/umargambari) for the full
set of repos.

## About

Built by Umar Gambari — security professional working toward security
engineering roles. Certifications: Security+, CySA+, SC-200, AZ-900,
Google Cloud Digital Leader, CCNA.
