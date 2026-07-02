# SOC2 Control: CC6.2
# IAM hardening — password policy, least-privilege, root alerts

resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}

resource "aws_iam_role" "app_role" {
  name = "${var.project_name}-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-app-role"
    SOC2Control = "CC6.2"
    Project     = var.project_name
  }
}

# Least-privilege policy — read only, specific resources
resource "aws_iam_policy" "least_privilege" {
  name        = "${var.project_name}-least-privilege"
  description = "Least privilege policy for app workloads"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ReadOnly"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.project_name}-encrypted-data",
          "arn:aws:s3:::${var.project_name}-encrypted-data/*"
        ]
      },
      {
        Sid    = "KMSDecryptOnly"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "app_role" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.least_privilege.arn
}

# SNS alert for root account usage
resource "aws_sns_topic" "root_alert" {
  name = "${var.project_name}-root-account-alert"

  tags = {
    Name        = "${var.project_name}-root-account-alert"
    SOC2Control = "CC6.2"
    Project     = var.project_name
  }
}
