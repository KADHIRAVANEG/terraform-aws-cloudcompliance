# SOC2 Control: CC6.3
# IAM Access Analyzer — detects overly permissive policies
# Note: aws_accessanalyzer_analyzer is Pro-only on LocalStack
# On real AWS: uncomment aws_accessanalyzer_analyzer resource below

# resource "aws_accessanalyzer_analyzer" "main" {
#   analyzer_name = "${var.project_name}-access-analyzer"
#   type          = "ACCOUNT"
#   tags = {
#     SOC2Control = "CC6.3"
#     Project     = var.project_name
#   }
# }

# Simulated via IAM role with read-only access analyzer permissions
resource "aws_iam_role" "access_analyzer" {
  name = "${var.project_name}-access-analyzer-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "access-analyzer.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Name        = "${var.project_name}-access-analyzer-role"
    SOC2Control = "CC6.3"
    Project     = var.project_name
  }
}

resource "aws_iam_role_policy" "access_analyzer" {
  name = "${var.project_name}-access-analyzer-policy"
  role = aws_iam_role.access_analyzer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "access-analyzer:ListAnalyzers",
        "access-analyzer:GetAnalyzer",
        "access-analyzer:ListFindings",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:GetServiceLastAccessedDetails"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_cloudwatch_metric_alarm" "access_analyzer_findings" {
  alarm_name          = "${var.project_name}-access-analyzer-findings"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "AccessAnalyzerFindings"
  namespace           = "CloudCompliance/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "SOC2 CC6.3 - IAM Access Analyzer finding detected"
  alarm_actions       = [var.sns_topic_arn]

  tags = {
    Name        = "${var.project_name}-access-analyzer-alarm"
    SOC2Control = "CC6.3"
    Project     = var.project_name
  }
}
