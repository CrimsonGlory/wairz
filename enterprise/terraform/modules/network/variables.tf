variable "name" {
  description = "Name prefix for network resources."
  type        = string
}

variable "aws_region" {
  description = "AWS region (for VPC endpoint service names)."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.42.0.0/16"
}

variable "create_nat_gateway" {
  description = "Use a NAT gateway for private egress instead of VPC endpoints. NAT is ~$32/mo; endpoints are cheaper at rest. See PLAN.md open decision #3."
  type        = bool
  default     = false
}

variable "extra_interface_endpoints" {
  description = "Additional interface VPC endpoint service short-names (e.g. \"cognito-idp\"). Only created on the no-NAT path."
  type        = list(string)
  default     = []
}
