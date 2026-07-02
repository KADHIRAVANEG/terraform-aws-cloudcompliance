output "kms_key_id" {
  value = aws_kms_key.main.key_id
}

output "kms_key_arn" {
  value = aws_kms_key.main.arn
}

output "encrypted_bucket_id" {
  value = aws_s3_bucket.encrypted_data.id
}

