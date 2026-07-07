terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  is_local = var.localstack_endpoint != ""
}

provider "aws" {
  region                      = var.aws_region
  access_key                  = local.is_local ? "test" : null
  secret_key                  = local.is_local ? "test" : null
  skip_credentials_validation = local.is_local
  skip_metadata_api_check     = local.is_local
  skip_requesting_account_id  = local.is_local
  s3_use_path_style           = local.is_local

  dynamic "endpoints" {
    for_each = local.is_local ? [1] : []
    content {
      s3              = var.localstack_endpoint
      cloudtrail      = var.localstack_endpoint
      kms             = var.localstack_endpoint
      iam             = var.localstack_endpoint
      ec2             = var.localstack_endpoint
      config          = var.localstack_endpoint
      sns             = var.localstack_endpoint
      cloudwatch      = var.localstack_endpoint
      cloudwatchlogs  = var.localstack_endpoint
      accessanalyzer  = var.localstack_endpoint
      backup          = var.localstack_endpoint
    }
  }
}
resource "aws_s3_bucket" "compliance_test" {
  bucket = "cloudcompliance-test"

  tags = {
    Project     = "CloudCompliance"
    Environment = "local"
    SOC2Control = "CC6.1"
  }
}
module "networking" {
  source             = "./modules/networking"
  project_name       = "cloudcompliance"
  vpc_cidr           = "10.0.0.0/16"
  availability_zones = ["us-east-1a", "us-east-1b"]
}
module "logging" {
  source       = "./modules/logging"
  project_name = "cloudcompliance"
  environment  = var.environment
}
module "encryption" {
  source       = "./modules/encryption"
  project_name = "cloudcompliance"
  environment  = var.environment
}
module "iam" {
  source       = "./modules/iam"
  project_name = "cloudcompliance"
}
module "monitoring" {
  source        = "./modules/monitoring"
  project_name  = "cloudcompliance"
  sns_topic_arn = module.iam.root_alert_topic_arn
}
module "config" {
  source          = "./modules/config"
  project_name    = "cloudcompliance"
  audit_bucket_id = module.logging.audit_bucket_id
}
module "access_analyzer" {
  source        = "./modules/access_analyzer"
  project_name  = var.project_name
  sns_topic_arn = module.iam.root_alert_topic_arn
}

module "incident_response" {
  source        = "./modules/incident_response"
  project_name  = var.project_name
  sns_topic_arn = module.iam.root_alert_topic_arn
}

module "availability" {
  source       = "./modules/availability"
  project_name = var.project_name
}
