###############################################################################
# modules/vpc
# A real, complete VPC. Public subnets AND private subnets, an internet gateway,
# public routing, and an interface-endpoint security group. Pillar 2 cannot put
# a Bedrock VPC endpoint anywhere without the private subnets and this SG, so
# they exist here from day one. This is the piece the old course left half-built.
###############################################################################

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name_prefix}-vpc" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name_prefix}-igw" }
}

resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "${var.name_prefix}-public-${count.index}" }
}

resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]

  tags = { Name = "${var.name_prefix}-private-${count.index}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = { Name = "${var.name_prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private route table with no 0.0.0.0/0 route. Private subnets stay private.
# Pillars reach AWS services through interface endpoints, not a NAT gateway,
# which also keeps the lab cheap.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name_prefix}-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Security group for interface VPC endpoints. In baseline the ingress CIDR is
# the whole internet (weak). In hardened it is the VPC CIDR only.
resource "aws_security_group" "endpoint" {
  name        = "${var.name_prefix}-endpoint-sg"
  description = "Interface endpoint access on 443"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "HTTPS to interface endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.endpoint_ingress_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-endpoint-sg" }
}

# VPC Flow Logs. Off in baseline (you are blind to the network), on in hardened.
resource "aws_flow_log" "this" {
  count           = var.enable_flow_logs ? 1 : 0
  log_destination = var.flow_logs_group_arn
  iam_role_arn    = var.flow_logs_role_arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.this.id
}
