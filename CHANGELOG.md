# Changelog

All notable changes to the `cloudcompliance` project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.3.0] - 2026-11-11

### Added
- **Prometheus & OpenTelemetry `/metrics` Exporter:** Standard exposition format endpoint on `cloudcompliance serve` (`GET /metrics`) and CLI (`cloudcompliance metrics`) emitting compliance scores, controls status, drift counts, and auto-remediation counters.
- **Grafana Dashboard Template:** Added production-ready Grafana Dashboard JSON (`dashboards/grafana_compliance_dashboard.json`) for instant visualization and alerting.
- **True Multi-Cloud Starter IaC:** Extended `cloudcompliance init` to generate complete, compliant Terraform configurations for:
  - **Azure (`azurerm`):** Key Vault with purge protection, Storage Account with TLS 1.2 & versioning, Network Security Groups, and Log Analytics.
  - **GCP (`google`):** Cloud KMS KeyRing with 90-day rotation, GCS bucket versioning, custom VPC, and Cloud Audit logging.
- **Multi-LLM AI Assistant (`cloudcompliance ask`):** Provider-agnostic compliance guidance supporting OpenAI (`gpt-4o`), Anthropic Claude (`claude-3-5-sonnet`), AWS Bedrock, local air-gapped Ollama, NVIDIA NIM, and deterministic offline rule evaluation.
- **Deep Instance-Level Attribute Evaluator:** Upgraded evaluation engine in `cloudcompliance/report.py` to inspect actual resource attributes (unrestricted SSH/RDP ingress, unencrypted RDS, unencrypted EBS, public databases, and disabled KMS key rotation).

### Security
- **Dashboard CORS Lockdown & API Token Authentication:** Restricted default CORS origins to local hosts and added Bearer/X-API-Key/Query token authentication (`CLOUDCOMPLIANCE_API_KEY` or `--token`).
- **Dashboard Path Traversal Prevention:** Whitelist validation on framework parameters.
- **Container Hardening:** Updated `Dockerfile` to enforce non-root user execution (`compliance:compliance`, UID 10001) complying with CIS Docker Benchmark 4.1.
- **Terraform Checkov Hardening:** Configured KMS CMK encryption for SNS topic and Lambda environment variables, added SQS Dead-Letter Queue (DLQ), reserved concurrency, and X-Ray active tracing.
- **Evidence Partitioning:** Partitioned SQLite compliance history by framework with automated schema migration.

---

## [2.2.0] - 2026-11-10

### Added
- **GitHub Code Scanning & SARIF Export (`--sarif` / `--format sarif`):** OASIS SARIF v2.1.0 output for GitHub Security alerts.
- **Interactive Starter Wizard (`cloudcompliance init`):** Interactive terminal wizard scaffolding compliant IaC.
- **Multi-Region CSPM Scanning (`scan --live --all-regions`):** Multi-region AWS API audit.
- **Multi-Channel Alerting:** Webhook dispatches to Slack, Microsoft Teams, Discord, and Generic/PagerDuty endpoints.

---

## [2.1.0] - 2026-10-31

### Added
- Signed Executive Auditor PDF Report generator (`--pdf`).
- GitHub PR Compliance Bot & Composite Action (`action.yml`).
- Agentless live AWS scanner (`scan --live`).
- Interactive web dashboard (`cloudcompliance serve`).

---

## [2.0.0] - 2026-07-17

### Added
- Multi-framework support for HIPAA Security Rule and PCI-DSS v4.0.
- Automatic infrastructure drift remediation engine (`cloudcompliance remediate`).
- Root module configuration for Terraform Registry publishing.
- LocalStack container integration in CI.
