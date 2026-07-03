# SOC2 Control: CC7.2
# Audit logging — tamper-evident S3 bucket
# Note: CloudTrail simulated via bucket policy (LocalStack free tier limitation)
# On real AWS: aws_cloudtrail resource replaces aws_s3_bucket_policy below

resource "aws_s3_bucket" "audit_logs" {
  bucket        = "${var.project_name}-audit-logs"
  force_destroy = var.environment == "local" ? true : false

  tags = {
    Name        = "${var.project_name}-audit-logs"
    SOC2Control = "CC7.2"
    Project     = var.project_name
  }
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Deny any delete of audit logs — tamper protection
resource "aws_s3_bucket_policy" "audit_logs_deny_delete" {
  bucket = aws_s3_bucket.audit_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyLogDeletion"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:DeleteObject", "s3:DeleteBucket"]
        Resource = [
          "arn:aws:s3:::${var.project_name}-audit-logs",
          "arn:aws:s3:::${var.project_name}-audit-logs/*"
        ]
      },
      {
        Sid       = "DenyNonHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "arn:aws:s3:::${var.project_name}-audit-logs",
          "arn:aws:s3:::${var.project_name}-audit-logs/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
