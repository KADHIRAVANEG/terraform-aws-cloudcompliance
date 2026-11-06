# Complete Example

Deploys the full SOC2 baseline — all 10 controls and 46 resources — in a single module call.

## Usage

```hcl
module "cloudcompliance" {
  source  = "KADHIRAVANEG/cloudcompliance/aws"
  version = "~> 2.0"

  project_name = "my-startup"
  environment  = "prod"
  aws_region   = "us-east-1"
}
```

## What gets deployed

- Private VPC with 2 subnets & deny-all security group (CC6.1)
- IAM password policy + least-privilege role + SNS alerts (CC6.2)
- Access Revocation & IAM Access Analyzer (CC6.3)
- HTTPS-only TLS S3 policies (CC6.6)
- KMS encryption at rest with automated key rotation (CC6.7)
- Threat detection alarms + Config rules (CC7.1)
- Versioned tamper-evident audit bucket + flow logs (CC7.2)
- Incident response log metric filters (CC7.3)
- IaC-controlled change management (CC8.1)
- Availability, automated backups & version retention (A1.1)
