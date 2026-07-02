output "app_role_arn" {
  value = aws_iam_role.app_role.arn
}

output "root_alert_topic_arn" {
  value = aws_sns_topic.root_alert.arn
}
