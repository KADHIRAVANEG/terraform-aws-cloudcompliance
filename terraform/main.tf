terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true

  endpoints {
    s3         = "http://localhost:4566"
    cloudtrail = "http://localhost:4566"
    kms        = "http://localhost:4566"
    iam        = "http://localhost:4566"
    ec2        = "http://localhost:4566"
    guardduty  = "http://localhost:4566"
    config     = "http://localhost:4566"
    sns        = "http://localhost:4566"
    cloudwatch = "http://localhost:4566"
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
}
module "encryption" {
  source       = "./modules/encryption"
  project_name = "cloudcompliance"
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
