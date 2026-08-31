# cloud-secops-platform (case study)

> Full Terraform/Bicep source lives in its own repo. This is a summary card
> for the portfolio — see **"Linking in the full code"** below to pull the
> complete project in here instead.

A phased cloud security operations build, structured around a real
Security Operations Engineer job description. Includes a phase checklist,
an architecture doc with a Mermaid diagram, an ADR, and a JD-to-deliverable
map showing how each phase satisfies a specific requirement in the posting.

## Phase 1 — Secure landing zone ✅

- VPC and network segmentation via Terraform
- IAM/RBAC least-privilege design
- GitHub OIDC CI/CD (no static cloud credentials in the pipeline)

## Phase 2 — SIEM/SOAR ✅

- Microsoft Sentinel detection rules, written as code (`azurerm`)
- Microsoft Defender for Endpoint integration
- Logic Apps playbook automating response: AbuseIPDB enrichment on
  suspicious IPs, and Graph API calls to disable compromised Entra ID users
- IaC via Bicep

## Phase 3 — Incident response (next)

IR runbook, a host triage toolkit simulation, and a post-incident
hardening report.

## Why it's relevant

Directly demonstrates the SIEM/SOAR and infrastructure-as-code skills an
AWS Security Incident Response role needs, even though this particular
build used Azure-native tooling — the detection-as-code and
automated-response patterns transfer directly.

## Linking in the full code

To pull the complete source into this repo, either add it as a git
submodule pointing at the standalone repo, or copy the source in directly.
