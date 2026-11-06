# CloudCompliance — SOC2-Ready AWS Infrastructure Baseline
# Terraform Registry module: KADHIRAVANEG/cloudcompliance/aws

module "compliance_baseline" {
  source = "./terraform"

  environment         = var.environment
  project_name        = var.project_name
  aws_region          = var.aws_region
  localstack_endpoint = var.localstack_endpoint
}
