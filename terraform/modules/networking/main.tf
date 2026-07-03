# SOC2 Control: CC6.1
# Private VPC — no public subnet exposure

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.project_name}-vpc"
    SOC2Control = "CC6.1"
    Project     = var.project_name
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = var.availability_zones[count.index]

  map_public_ip_on_launch = false

  tags = {
    Name        = "${var.project_name}-private-${count.index}"
    SOC2Control = "CC6.1"
    Type        = "private"
  }
}

resource "aws_default_security_group" "deny_all" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "${var.project_name}-deny-all"
    SOC2Control = "CC6.1"
  }
}
# VPC Flow Logs — CC7.2
resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn

  tags = {
    Name        = "${var.project_name}-flow-logs"
    SOC2Control = "CC7.2"
    Project     = var.project_name
  }
}

resource "aws_cloudwatch_log_group" "flow_log" {
  name              = "/aws/vpc/${var.project_name}-flow-logs"
  retention_in_days = 90

  tags = {
    SOC2Control = "CC7.2"
    Project     = var.project_name
  }
}

resource "aws_iam_role" "flow_log" {
  name = "${var.project_name}-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    SOC2Control = "CC7.2"
    Project     = var.project_name
  }
}

resource "aws_iam_role_policy" "flow_log" {
  name = "${var.project_name}-flow-log-policy"
  role = aws_iam_role.flow_log.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}
