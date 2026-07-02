variable "project_name" {
  type    = string
  default = "cloudcompliance"
}

variable "sns_topic_arn" {
  type        = string
  description = "SNS topic ARN for security alerts"
}
