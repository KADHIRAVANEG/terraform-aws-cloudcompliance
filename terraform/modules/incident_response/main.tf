# SOC2 Control: CC7.3
# Incident response — log metric filters + automated alerts

resource "aws_cloudwatch_log_group" "security_events" {
  name              = "/cloudcompliance/${var.project_name}/security-events"
  retention_in_days = 365

  tags = {
    Name        = "${var.project_name}-security-events"
    SOC2Control = "CC7.3"
    Project     = var.project_name
  }
}

resource "aws_cloudwatch_log_metric_filter" "unauthorized_api" {
  name           = "${var.project_name}-unauthorized-api-calls"
  log_group_name = aws_cloudwatch_log_group.security_events.name
  pattern        = "{ $.errorCode = \"AccessDenied\" || $.errorCode = \"UnauthorizedAccess\" }"

  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = "CloudCompliance/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "console_signin_failure" {
  name           = "${var.project_name}-console-signin-failure"
  log_group_name = aws_cloudwatch_log_group.security_events.name
  pattern        = "{ $.eventName = \"ConsoleLogin\" && $.errorMessage = \"Failed authentication\" }"

  metric_transformation {
    name      = "ConsoleSignInFailures"
    namespace = "CloudCompliance/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api" {
  alarm_name          = "${var.project_name}-unauthorized-api-calls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedAPICalls"
  namespace           = "CloudCompliance/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "SOC2 CC7.3 - Unauthorized API calls detected"
  alarm_actions       = [var.sns_topic_arn]

  tags = {
    Name        = "${var.project_name}-unauthorized-api-alarm"
    SOC2Control = "CC7.3"
    Project     = var.project_name
  }
}

resource "aws_cloudwatch_metric_alarm" "console_signin_failure" {
  alarm_name          = "${var.project_name}-console-signin-failure"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ConsoleSignInFailures"
  namespace           = "CloudCompliance/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  alarm_description   = "SOC2 CC7.3 - Console sign-in failures detected"
  alarm_actions       = [var.sns_topic_arn]

  tags = {
    Name        = "${var.project_name}-console-signin-alarm"
    SOC2Control = "CC7.3"
    Project     = var.project_name
  }
}
