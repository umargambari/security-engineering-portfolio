# aws-detection-pipeline (case study)

> Full Terraform and Lambda source lives in its own repo. This is a summary
> card for the portfolio — see **"Linking in the full code"** below to pull
> the complete project in here instead.

## What it does

An automated threat detection and response pipeline built on native AWS
security services:

```
GuardDuty  --->  EventBridge  --->  Lambda  --->  DynamoDB (finding history)
                                        |
                                        +----> SNS (alerting)
```

- **GuardDuty** continuously monitors for malicious/unauthorized activity
  across the AWS account.
- **EventBridge** rules route qualifying GuardDuty findings to a Lambda
  function in near real time.
- **Lambda** enriches and triages the finding, writes a record to
  **DynamoDB** for history/audit, and publishes an alert via **SNS**.
- Infrastructure is defined entirely in **Terraform**.
- CI/CD deploys via **GitHub OIDC** — no long-lived AWS credentials stored
  in GitHub Actions.

## Why it's relevant

This maps directly onto the day-to-day of an AWS-focused Security
Incident Response role: tracking GuardDuty findings, automating triage so
humans aren't the first line of defense against every alert, and keeping
the deployment pipeline itself credential-free.

## Linking in the full code

To pull the complete Terraform/Lambda source into this repo (rather than
just this summary), either:
- add it as a git submodule pointing at the standalone repo, or
- copy the source in directly and I can help restructure it to sit
  alongside the Python tools with a consistent layout.
