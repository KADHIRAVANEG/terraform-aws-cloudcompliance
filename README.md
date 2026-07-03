![SOC2 Compliance](https://github.com/KADHIRAVANEG/Cloud-Compliance/actions/workflows/compliance.yml/badge.svg)
![Terraform](https://img.shields.io/badge/Terraform-1.15.6-7B42BC?logo=terraform)
![LocalStack](https://img.shields.io/badge/LocalStack-3.4.0-000000?logo=amazon-aws)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)

# CloudCompliance — SOC2-Ready AWS IaC

> Infrastructure as Code that provisions a SOC2-aligned AWS security baseline
> in one command. Zero manual security configuration required.

## The Problem

Startups spend 6–12 months retrofitting SOC2 controls onto infrastructure that
was never designed to be compliant. Security is an afterthought — CloudTrail
gets enabled after an incident, encryption gets added before an audit, RBAC
gets tightened only when required.

**This IaC eliminates that retrofit entirely.**
Every SOC2 control is provisioned automatically at infrastructure creation time.

---

## SOC2 Control Coverage

| Control | Title                             | Resources Enforced                                              |
|---------|-----------------------------------|-----------------------------------------------------------------|
| CC6.1   | Network Isolation                 | VPC, private subnets, deny-all security group                   |
| CC6.2   | Authentication Controls           | IAM password policy, MFA alert, least-privilege role            |
| CC6.6   | Transmission Protection           | HTTPS-only S3 bucket policy, TLS enforcement                    |
| CC6.7   | Encryption at Rest                | KMS CMK, S3 server-side encryption, encrypted data bucket       |
| CC7.1   | Threat Detection                  | CloudWatch alarms, AWS Config recorder, Config rules            |
| CC7.2   | Audit Logging                     | Versioned audit bucket, delete protection, Config delivery      |
| CC8.1   | Change Management                 | IaC-controlled infra, Config recorder status tracking           |


> **Scope note:** This IaC implements the *technical infrastructure controls* 
> mapped to SOC2 Common Criteria CC6-CC8. Full SOC2 Type II certification 
> additionally requires organizational policies, vendor management, employee 
> training, and 6-12 months of evidence collection — which are outside the 
> scope of infrastructure code.

---

## What Gets Provisioned (29 resources)

### Networking — CC6.1
- Private VPC (`10.0.0.0/16`) with 2 private subnets
- No public subnets — zero internet exposure by default
- Default-deny security group — all inbound/outbound blocked

### Logging — CC7.2
- Dedicated audit S3 bucket with versioning enabled
- Delete protection policy — no object or bucket deletion allowed
- HTTPS-only access policy on audit bucket

### Encryption — CC6.7
- KMS Customer Managed Key (CMK) with automatic key rotation
- S3 encrypted data bucket with KMS SSE
- HTTPS-only bucket policy — plaintext requests denied

### IAM — CC6.2
- Account password policy: 14 chars, complexity, 90-day rotation, 24 history
- Least-privilege IAM role — S3 read + KMS decrypt only
- SNS topic for root account usage alerts

### Monitoring — CC7.1
- CloudWatch alarm: root account login detection
- CloudWatch alarm: public S3 bucket detection
- Both wired to SNS alert topic

### Config — CC7.1 + CC7.2
- AWS Config recorder — all resource types, all regions
- Config delivery channel → audit S3 bucket
- Config rules: S3 public read prohibited, S3 encryption required, root MFA

---

## Quick Start

**Requirements:** Terraform ≥ 1.15, Docker

```bash
# 1. Start LocalStack (free local AWS)
docker run --rm -d -p 4566:4566 localstack/localstack:3.4.0

# 2. Deploy all SOC2 controls
make deploy

# 3. Generate compliance evidence report
make report
```

**Expected output:**

```
╭────────────────────────────────────────╮
│ CloudCompliance — SOC2 Evidence Report │
│ Total resources provisioned: 29        │
╰────────────────────────────────────────╯
SOC2 Compliance Score: 100% (7/7 controls passing)
```

---

## Project Structure

```
cloudcompliance/
├── terraform/
│   ├── main.tf                  # Root — calls all modules
│   ├── variables.tf             # Environment, region, endpoint
│   ├── backend.tf               # Local (dev) / S3 (prod) backend
│   ├── local.tfvars             # LocalStack config
│   ├── prod.tfvars              # Real AWS config
│   └── modules/
│       ├── networking/          # CC6.1 — VPC, subnets, SGs
│       ├── logging/             # CC7.2 — Audit bucket
│       ├── encryption/          # CC6.7 — KMS, encrypted S3
│       ├── iam/                 # CC6.2 — Password policy, roles
│       ├── monitoring/          # CC7.1 — CloudWatch alarms
│       └── config/              # CC7.1/7.2 — Config rules
├── compliance/
│   └── report.py                # SOC2 evidence generator
├── .github/workflows/
│   └── compliance.yml           # CI gate — blocks non-compliant PRs
└── Makefile                     # make deploy / report / destroy
```

---

## CI/CD Compliance Gate

Every pull request automatically:
1. Validates Terraform formatting and syntax
2. Deploys to LocalStack
3. Runs the compliance report
4. **Blocks merge if any SOC2 control is missing**

---

## Deploying to Real AWS

```bash
# 1. Configure AWS credentials
aws configure

# 2. Deploy to real AWS
make deploy-prod
```

For production, uncomment the S3 backend in `terraform/backend.tf`
to enable remote state with DynamoDB locking.

---

## LocalStack vs Real AWS

| Feature              | LocalStack (free) | Real AWS |
|----------------------|-------------------|----------|
| VPC / Subnets        | ✅                | ✅       |
| S3 + Encryption      | ✅                | ✅       |
| KMS                  | ✅                | ✅       |
| IAM                  | ✅                | ✅       |
| CloudWatch           | ✅                | ✅       |
| AWS Config           | ✅                | ✅       |
| SNS                  | ✅                | ✅       |
| CloudTrail           | ⚠️ Pro only       | ✅       |
| GuardDuty            | ⚠️ Pro only       | ✅       |

---

## Standards Referenced

- [AICPA SOC2 Trust Services Criteria 2017](https://www.aicpa.org/resources/landing/system-and-organization-controls-soc-suite-of-services)
- [CIS AWS Foundations Benchmark v2.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [NIST SP 800-53 Rev 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)
- [AWS Security Reference Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html)

---

## Tech Stack

`Terraform` · `Python` · `AWS` · `LocalStack` · `GitHub Actions` · `KMS` · `IAM` · `CloudWatch` · `SNS` · `AWS Config`

---

## Author

**Kadhiravan E.G.** — 3rd year Cybersecurity student  
GitHub: [@KADHIRAVANEG](https://github.com/KADHIRAVANEG)
