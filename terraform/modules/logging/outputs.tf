output "audit_bucket_id" {
  value = aws_s3_bucket.audit_logs.id
}

output "audit_bucket_arn" {
  value = aws_s3_bucket.audit_logs.arn
}
