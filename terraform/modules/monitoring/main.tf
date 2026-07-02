# SOC2 Control: CC7.1
# Continuous monitoring via CloudWatch alarms
# Note: GuardDuty simulated (LocalStack free tier limitation)
# On real AWS: add aws_guardduty_detector resource

resource "aws_cloudwatch_metric_alarm" "root_login" {
  alarm_name          = "${var.project_name}-root-login-detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = "CloudCompliance/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "SOC2 CC7.1 - Root account login detected"
  alarm_actions       = [var.sns_topic_arn]

  tags = {
    Name        = "${var.project_name}-root-login-alarm"
    SOC2Control = "CC7.1"
    Project     = var.project_name
  }
}

resource "aws_cloudwatch_metric_alarm" "public_bucket" {
  alarm_name          = "${var.project_name}-public-bucket-detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "PublicBucketAccess"
  namespace           = "CloudCompliance/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "SOC2 CC7.1 - Public S3 bucket detected"
  alarm_actions       = [var.sns_topic_arn]

  tags = {
    Name        = "${var.project_name}-public-bucket-detected"
    SOC2Control = "CC7.1"
    Project     = var.project_name
  }
}
