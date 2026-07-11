variable "name" {
  type        = string
  description = "Name prefix."
}

variable "spa_bucket" {
  type        = string
  description = "SPA S3 bucket name."
}

variable "spa_bucket_arn" {
  type        = string
  description = "SPA S3 bucket ARN."
}

variable "spa_bucket_regional_domain_name" {
  type        = string
  description = "SPA S3 bucket regional domain name (CloudFront origin)."
}

variable "alb_dns_name" {
  type        = string
  description = "Backend ALB DNS name (API origin)."
}

variable "price_class" {
  type        = string
  default     = "PriceClass_100"
  description = "CloudFront price class."
}

variable "aliases" {
  type        = list(string)
  default     = []
  description = "Custom domain aliases (requires acm_certificate_arn)."
}

variable "acm_certificate_arn" {
  type        = string
  default     = ""
  description = "ACM cert ARN (us-east-1) for custom domains. Empty = use the default *.cloudfront.net cert."
}

variable "mcp_enabled" {
  type        = bool
  default     = false
  description = "Add an uncached /mcp* CloudFront behavior routing the Streamable HTTP MCP transport to the ALB (Phase 5)."
}
