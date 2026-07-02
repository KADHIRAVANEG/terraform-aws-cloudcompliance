# SOC2 Control: CC6.7
# Encryption at rest (KMS) and in transit (HTTPS-only policy)

resource "aws_kms_key" "main" {
  description             = "${var.project_name} customer managed key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name        = "${var.project_name}-cmk"
    SOC2Control = "CC6.7"
    Project     = var.project_name
  }
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.project_name}-cmk"
  target_key_id = aws_kms_key.main.key_id
}

resource "aws_s3_bucket" "encrypted_data" {
  bucket        = "${var.project_name}-encrypted-data"
  force_destroy = true

  tags = {
    Name        = "${var.project_name}-encrypted-data"
    SOC2Control = "CC6.7"
    Project     = var.project_name
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encrypted_data" {
  bucket = aws_s3_bucket.encrypted_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "encrypted_data" {
  bucket = aws_s3_bucket.encrypted_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "https_only" {
  bucket = aws_s3_bucket.encrypted_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          "arn:aws:s3:::${var.project_name}-encrypted-data",
          "arn:aws:s3:::${var.project_name}-encrypted-data/*"
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
