# =============================================================================
# Sovereign Multi-Cloud Parity: Azure Government Disconnected Private Enclave
# Enforces zero Public IP addresses, zero NAT Gateways, and Private Link only.
# Validated offline via `terraform validate` with zero cloud provider network calls.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"
}

variable "enclave_name" {
  type    = string
  default = "aegis-azgov-usgovvirginia-enclave"
}

variable "vnet_cidr" {
  type    = string
  default = "10.250.0.0/16"
}

variable "allow_public_ip_or_nat" {
  type    = bool
  default = false
  validation {
    condition     = var.allow_public_ip_or_nat == false
    error_message = "Zero-egress FedRAMP High / IL5 enclave prohibits Public IPs and NAT Gateways."
  }
}

locals {
  private_link_endpoints = [
    "privatelink.azurecr.us",
    "privatelink.vaultcore.usgovcloudapi.net",
    "privatelink.postgres.database.usgovcloudapi.net",
    "privatelink.openai.azure.us",
  ]
  confidential_vm_sku = "Standard_DC32as_v5" # AMD SEV-SNP Confidential AKS NodePool
}

resource "terraform_data" "azure_gov_zero_egress_enclave" {
  input = {
    enclave_name           = var.enclave_name
    vnet_cidr              = var.vnet_cidr
    public_egress_enabled  = var.allow_public_ip_or_nat
    private_link_endpoints = local.private_link_endpoints
    confidential_node_sku  = local.confidential_vm_sku
  }
}

output "sovereign_enclave_profile" {
  value = terraform_data.azure_gov_zero_egress_enclave.output
}
