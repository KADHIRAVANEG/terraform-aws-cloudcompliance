# CloudCompliance — SOC2 Evidence Report

**Generated:** 2026-07-12 12:16:02  
**Total resources provisioned:** 46  
**Compliance score:** 100% (10/10 controls passing)

## Control Coverage

| Control | Title | Status | Matched Resources |
|---------|-------|--------|-------------------|
| CC6.1 | Logical Access — Network Isolation | ✅ PASS | aws_vpc, aws_subnet, aws_default_security_group |
| CC6.2 | Logical Access — Authentication Controls | ✅ PASS | aws_iam_account_password_policy, aws_iam_role, aws_iam_policy |
| CC6.3 | Logical Access — Access Revocation | ✅ PASS | aws_iam_role_policy, aws_cloudwatch_metric_alarm |
| CC6.6 | Logical Access — Transmission Protection | ✅ PASS | aws_s3_bucket_policy |
| CC6.7 | Encryption — Data Protection | ✅ PASS | aws_kms_key, aws_kms_alias, aws_s3_bucket_server_side_encryption_configuration |
| CC7.1 | Threat Detection — Continuous Monitoring | ✅ PASS | aws_cloudwatch_metric_alarm, aws_config_configuration_recorder, aws_config_config_rule |
| CC7.2 | Audit Logging — Tamper-evident Records | ✅ PASS | aws_s3_bucket_versioning, aws_s3_bucket_public_access_block, aws_config_delivery_channel |
| CC7.3 | Incident Response — Security Event Detection | ✅ PASS | aws_cloudwatch_log_metric_filter, aws_cloudwatch_log_group |
| CC8.1 | Change Management — IaC Controlled | ✅ PASS | aws_iam_role, aws_config_configuration_recorder_status |
| A1.1 | Availability — Backup and Retention | ✅ PASS | aws_s3_bucket_versioning, aws_iam_role_policy_attachment |

## Summary

SOC2 Compliance Score: **100%** (10/10 controls passing)

## Standards Referenced

- AICPA SOC2 Trust Services Criteria 2017
- CIS AWS Foundations Benchmark v2.0
- NIST SP 800-53 Rev 5
