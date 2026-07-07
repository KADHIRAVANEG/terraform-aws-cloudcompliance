output "security_log_group_name" {
  value = aws_cloudwatch_log_group.security_events.name
}

output "unauthorized_api_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.unauthorized_api.arn
}

