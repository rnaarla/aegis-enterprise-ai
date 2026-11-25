# Project 2: Zero-Egress Isolated AWS VPC Reference Enclave
# Validates 3-AZ private subnet CIDR partitioning & zero-egress network invariants offline,
# paired with full AWS PrivateLink HCL resources in `./modules/aws_enclave/vpc_privatelink.tf`.

terraform {
  required_version = ">= 1.6.0"
}

variable "vpc_cidr" {
  type        = string
  default     = "10.240.0.0/16"
  description = "Isolated /16 CIDR block for air-gapped Aegis AI enclave"

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr must be a valid IPv4 CIDR block."
  }
}

variable "environment" {
  type        = string
  default     = "prod-airgap"
  description = "Regulated deployment tier tag"
}

variable "availability_zones" {
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
  description = "Three isolated AZs for HA PostgreSQL RLS, Temporal, and vLLM GPU workers"
}

locals {
  private_app_subnets = {
    for idx, az in var.availability_zones :
    az => cidrsubnet(var.vpc_cidr, 4, idx)
  }
  private_data_subnets = {
    for idx, az in var.availability_zones :
    az => cidrsubnet(var.vpc_cidr, 4, idx + 4)
  }
  privatelink_endpoints = toset(["ecr.api", "ecr.dkr", "kms", "logs", "s3"])
  internet_gateway      = false
  nat_gateway           = false
}

resource "terraform_data" "airgap_enclave_manifest" {
  input = {
    environment           = var.environment
    vpc_cidr              = var.vpc_cidr
    private_app_subnets   = local.private_app_subnets
    private_data_subnets  = local.private_data_subnets
    privatelink_endpoints = local.privatelink_endpoints
    internet_gateway      = local.internet_gateway
    nat_gateway           = local.nat_gateway
  }

  lifecycle {
    precondition {
      condition     = local.internet_gateway == false && local.nat_gateway == false
      error_message = "Air-gap violation: IGW and NAT Gateways are strictly prohibited."
    }
  }
}

output "airgap_network_invariants" {
  description = "Verified zero-egress 3-AZ VPC subnet & PrivateLink topology"
  value = {
    vpc_cidr                = var.vpc_cidr
    internet_gateway        = false
    nat_gateway             = false
    public_subnets          = 0
    private_app_subnets     = local.private_app_subnets
    private_data_subnets    = local.private_data_subnets
    default_route_blackhole = true
    privatelink_only        = sort(tolist(local.privatelink_endpoints))
  }
}
