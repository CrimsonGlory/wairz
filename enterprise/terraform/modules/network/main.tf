# Network module — VPC, public + private subnets across 2 AZs, and the VPC
# endpoints that let private workloads (ECS, Batch) reach AWS services without
# a NAT gateway (the cheaper-at-rest default; set create_nat_gateway=true to
# use NAT instead). See enterprise/PLAN.md open decision #3.

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs             = slice(data.aws_availability_zones.available.names, 0, 2)
  public_subnets  = [for i, _ in local.azs : cidrsubnet(var.vpc_cidr, 4, i)]
  private_subnets = [for i, _ in local.azs : cidrsubnet(var.vpc_cidr, 4, i + 8)]
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.name }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = var.name }
}

resource "aws_subnet" "public" {
  count                   = length(local.azs)
  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.public_subnets[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true
  tags                    = { Name = "${var.name}-public-${local.azs[count.index]}", Tier = "public" }
}

resource "aws_subnet" "private" {
  count             = length(local.azs)
  vpc_id            = aws_vpc.this.id
  cidr_block        = local.private_subnets[count.index]
  availability_zone = local.azs[count.index]
  tags              = { Name = "${var.name}-private-${local.azs[count.index]}", Tier = "private" }
}

# --- Public routing ---------------------------------------------------------
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = { Name = "${var.name}-public" }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# --- Private routing --------------------------------------------------------
# One NAT gateway (optional) for egress, else private subnets reach AWS APIs
# only via the interface/gateway endpoints below.
resource "aws_eip" "nat" {
  count  = var.create_nat_gateway ? 1 : 0
  domain = "vpc"
  tags   = { Name = "${var.name}-nat" }
}

resource "aws_nat_gateway" "this" {
  count         = var.create_nat_gateway ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = var.name }
  depends_on    = [aws_internet_gateway.this]
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  dynamic "route" {
    for_each = var.create_nat_gateway ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.this[0].id
    }
  }
  tags = { Name = "${var.name}-private" }
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# --- Security groups --------------------------------------------------------
# Shared SG for VPC endpoints: allow HTTPS from inside the VPC.
resource "aws_security_group" "endpoints" {
  name_prefix = "${var.name}-vpce-"
  description = "HTTPS to interface VPC endpoints from within the VPC"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.this.cidr_block]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-vpce" }
}

# --- VPC endpoints (no-NAT egress to AWS services) --------------------------
# Gateway endpoint: S3 (free; used by ECR layer pulls + app artifact access).
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  tags              = { Name = "${var.name}-s3" }
}

# Interface endpoints: ECR (api + dkr), Secrets Manager, CloudWatch Logs, STS.
# These let Fargate/Batch pull images, read secrets, and log without NAT.
locals {
  interface_endpoints = toset(concat([
    "ecr.api",
    "ecr.dkr",
    "secretsmanager",
    "logs",
    "sts",
    # EC2-backed AWS Batch instances run the ECS agent, which must reach the
    # ECS control plane to register + run tasks. Without these (and with no NAT)
    # instances launch but never join the cluster, so Batch jobs hang in
    # RUNNABLE. Fargate doesn't need these (AWS manages its control plane link).
    "ecs",
    "ecs-agent",
    "ecs-telemetry",
    # The Batch CONTROL-PLANE API: the backend/MCP sidecar calls batch:SubmitJob
    # + DescribeJobs to dispatch and poll Ghidra analysis. Without this (and no
    # NAT) those boto3 calls have no route and hang until timeout — blocking the
    # caller (and the MCP sidecar's event loop → ECS health-check reap) and never
    # creating a job. Distinct from the "ecs" endpoints above (which are for the
    # Batch *compute instances*, not the API the dispatcher calls).
    "batch",
    # Caller-supplied extras (e.g. "cognito-idp" so the backend can fetch the
    # OIDC JWKS privately when auth is enabled). No-op under NAT (for_each below
    # is empty then).
  ], var.extra_interface_endpoints))
}

# Not every service supports every AZ (e.g. cognito-idp). Look up each service's
# supported AZs so we only place its endpoint in matching subnets — a single-AZ
# interface endpoint still serves the whole VPC via private DNS.
data "aws_vpc_endpoint_service" "interface" {
  for_each     = var.create_nat_gateway ? toset([]) : local.interface_endpoints
  service      = each.value
  service_type = "Interface"
}

resource "aws_vpc_endpoint" "interface" {
  for_each          = var.create_nat_gateway ? toset([]) : local.interface_endpoints
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type = "Interface"
  subnet_ids = [
    for s in aws_subnet.private : s.id
    if contains(data.aws_vpc_endpoint_service.interface[each.value].availability_zones, s.availability_zone)
  ]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = { Name = "${var.name}-${each.value}" }
}
