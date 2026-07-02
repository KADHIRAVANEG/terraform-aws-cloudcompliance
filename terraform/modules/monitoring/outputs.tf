output "root_login_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.root_login.arn
}

output "public_bucket_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.public_bucket.arn
}
