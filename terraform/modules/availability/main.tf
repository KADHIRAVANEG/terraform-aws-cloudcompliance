# SOC2 Control: A1.1
# Availability — retention policies, versioning, backup role

resource "aws_s3_bucket" "availability_logs" {
  bucket        = "${var.project_name}-availability-logs"
  force_destroy = true

  tags = {
    Name        = "${var.project_name}-availability-logs"
    SOC2Control = "A1.1"
    Project     = var.project_name
  }
}

resource "aws_s3_bucket_versioning" "availability_logs" {
  bucket = aws_s3_bucket.availability_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "availability_logs" {
  bucket = aws_s3_bucket.availability_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_role" "backup_role" {
  name = "${var.project_name}-backup-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    SOC2Control = "A1.1"
    Project     = var.project_name
  }
}

resource "aws_iam_role_policy_attachment" "backup_role" {
  role       = aws_iam_role.backup_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}
