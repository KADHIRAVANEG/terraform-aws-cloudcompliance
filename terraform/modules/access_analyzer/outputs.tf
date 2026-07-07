output "analyzer_role_arn" {
  value = aws_iam_role.access_analyzer.arn
}

output "findings_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.access_analyzer_findings.arn
}
