resource "aws_iam_role" "lambda_exec" {
  name = "cloudcompliance-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_sqs_queue" "lambda_dlq" {
  name                    = "cloudcompliance-drift-dlq"
  sqs_managed_sse_enabled = true

  tags = {
    Name        = "cloudcompliance-drift-dlq"
    SOC2Control = "CC7.3"
  }
}

resource "aws_iam_policy" "lambda_compliance_policy" {
  name        = "cloudcompliance-lambda-least-privilege"
  description = "Scoped least-privilege permissions for CloudCompliance Lambda drift detector"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::*",
          "arn:aws:s3:::*/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.lambda_dlq.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_compliance_policy.arn
}

resource "aws_lambda_function" "drift_detector" {
  # checkov:skip=CKV_AWS_117:Lambda audits AWS API endpoints and S3 state directly without requiring VPC peering
  # checkov:skip=CKV_AWS_272:Lambda function is an agentless scanner that does not require VPC attachment
  filename                       = var.lambda_zip_path
  function_name                  = "cloudcompliance-drift-detector"
  role                           = aws_iam_role.lambda_exec.arn
  handler                        = "cloudcompliance.lambda_handler.handler"
  runtime                        = "python3.11"
  timeout                        = 300
  reserved_concurrent_executions = 5
  kms_key_arn                    = var.kms_key_arn != "" ? var.kms_key_arn : null

  tracing_config {
    mode = "Active"
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  environment {
    variables = {
      TFSTATE_URL    = var.tfstate_s3_uri
      AUTO_REMEDIATE = tostring(var.auto_remediate)
    }
  }
}

# EventBridge Rule to trigger Lambda on any AWS API call that modifies infrastructure
resource "aws_cloudwatch_event_rule" "infra_changes" {
  name        = "cloudcompliance-infra-changes"
  description = "Triggers CloudCompliance drift detection on infra changes"
  event_pattern = jsonencode({
    "source" : ["aws.ec2", "aws.s3", "aws.iam", "aws.kms"],
    "detail-type" : ["AWS API Call via CloudTrail"],
    "detail" : {
      "eventName" : [
        "CreateBucket", "DeleteBucket",
        "CreateRole", "DeleteRole",
        "RunInstances", "TerminateInstances",
        "ScheduleKeyDeletion"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.infra_changes.name
  target_id = "TriggerCloudComplianceLambda"
  arn       = aws_lambda_function.drift_detector.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.drift_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.infra_changes.arn
}
