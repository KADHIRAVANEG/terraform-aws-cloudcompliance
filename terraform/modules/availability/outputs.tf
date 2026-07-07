output "availability_bucket_id" {
  value = aws_s3_bucket.availability_logs.id
}

output "backup_role_arn" {
  value = aws_iam_role.backup_role.arn
}
