# Production AWS Provider Module (Applied via Enterprise Private Terraform Registry Mirror)
# Zero `aws_internet_gateway`, Zero `aws_nat_gateway`, PrivateLink Interface/Gateway Endpoints Only.

variable "vpc_cidr" { type = string }
variable "aws_region" { type = string }
variable "private_subnets" { type = map(string) }

resource "aws_vpc" "aegis_airgap" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "aegis-zero-egress-vpc", AirGapped = "true" }
}

resource "aws_default_security_group" "lockdown" {
  vpc_id = aws_vpc.aegis_airgap.id
  # Empty ingress & egress blocks lock down default SG completely
}

resource "aws_subnet" "private_enclave" {
  for_each                = var.private_subnets
  vpc_id                  = aws_vpc.aegis_airgap.id
  availability_zone       = each.key
  cidr_block              = each.value
  map_public_ip_on_launch = false
}

resource "aws_route_table" "blackhole_egress" {
  vpc_id = aws_vpc.aegis_airgap.id
  # Local VPC routing only — zero 0.0.0.0/0 route!
  tags = { Name = "aegis-zero-public-egress-rt" }
}

resource "aws_security_group" "privatelink_tls" {
  name        = "aegis-privatelink-443"
  description = "Allow TLS 443 strictly from internal VPC CIDR"
  vpc_id      = aws_vpc.aegis_airgap.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
}

resource "aws_vpc_endpoint" "interface_endpoints" {
  for_each            = toset(["ecr.api", "ecr.dkr", "kms", "logs"])
  vpc_id              = aws_vpc.aegis_airgap.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [for s in aws_subnet.private_enclave : s.id]
  security_group_ids  = [aws_security_group.privatelink_tls.id]
}
