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
