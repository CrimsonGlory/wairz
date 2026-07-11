variable "name" {
  description = "Name prefix for backend resources."
  type        = string
}

variable "aws_region" {
  description = "AWS region (log/env config)."
  type        = string
}

variable "vpc_id" {
  type        = string
  description = "VPC id."
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "Public subnets for the ALB."
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnets for the Fargate tasks."
}

variable "container_port" {
  type        = number
  default     = 8000
  description = "Backend listen port."
}

variable "health_check_path" {
  type        = string
  default     = "/health"
  description = "ALB target-group health check path."
}

variable "task_cpu" {
  type        = number
  default     = 1024
  description = "Fargate task CPU units (1024 = 1 vCPU). Heavy Ghidra is on Batch, but in-process tools (strings/radare2/binwalk) on large images need real CPU so they don't starve the event loop (and the MCP /healthz)."
}

variable "task_memory" {
  type        = number
  default     = 4096
  description = "Fargate task memory (MiB). Firmware analysis on large images is memory-hungry; 1 GB OOMs. Must be a valid Fargate combo for task_cpu (1024 vCPU → 2048–8192)."
}

variable "desired_count" {
  type        = number
  default     = 1
  description = "Baseline / minimum task count (also the autoscaling floor)."
}

variable "max_count" {
  type        = number
  default     = 4
  description = "Autoscaling ceiling."
}

variable "cpu_target_percent" {
  type        = number
  default     = 60
  description = "Target average CPU % for autoscaling."
}

variable "image_tag" {
  type        = string
  default     = "latest"
  description = "Backend image tag in the module's ECR repo."
}

variable "max_upload_size_mb" {
  type        = number
  default     = 500
  description = "Max upload size (plumbs to the app + should match ALB/CloudFront)."
}

variable "batch_max_jobs_per_firmware" {
  type        = number
  default     = 8
  description = "Per-firmware in-flight Batch job cap enforced by the backend at SubmitJob (shared-instance fairness). 0 disables."
}

variable "auth_enabled" {
  type        = bool
  default     = false
  description = "Enforce OIDC bearer-token auth on the HTTP API."
}

variable "oidc_issuer" {
  type        = string
  default     = ""
  description = "OIDC issuer URL the backend validates tokens against (the Cognito pool by default)."
}

variable "oidc_audience" {
  type        = string
  default     = ""
  description = "Expected token audience / client id."
}

variable "allowed_hosts" {
  type        = string
  default     = "*"
  description = "App Host-guard allowlist (comma-separated; '*' disables). Default permissive since the API is fronted by CloudFront/ALB + Cognito."
}

variable "allowed_origins" {
  type        = string
  default     = "*"
  description = "App Origin-guard allowlist (comma-separated; '*' disables)."
}

variable "certificate_arn" {
  type        = string
  default     = ""
  description = "ACM cert ARN to enable an HTTPS listener (required for ALB-level Cognito auth). Empty = HTTP only (fine behind CloudFront)."
}

variable "log_retention_days" {
  type    = number
  default = 30
}

# --- Remote MCP sidecar (Phase 5) ------------------------------------------
variable "mcp_http_enabled" {
  type        = bool
  default     = false
  description = "Run the Streamable HTTP MCP server as a sidecar in the backend task and route /mcp* to it. Lets Claude connect to the cloud instance over HTTP (Cognito-gated) instead of stdio. Off = no MCP sidecar (local/stdio only)."
}

variable "mcp_container_port" {
  type        = number
  default     = 8765
  description = "Port the MCP sidecar listens on (ALB routes /mcp* here)."
}

variable "mcp_health_path" {
  type        = string
  default     = "/healthz"
  description = "Unauthenticated health path the MCP sidecar serves for the ALB target-group check."
}

# --- Wired from other modules ----------------------------------------------
variable "efs_id" {
  type = string
}

variable "efs_firmware_access_point_id" {
  type = string
}

variable "efs_ghidra_projects_access_point_id" {
  type = string
}

variable "redis_url" {
  type = string
}

variable "database_url_secret_arn" {
  type = string
}

variable "secret_arns" {
  type        = list(string)
  default     = []
  description = "Secret ARNs the execution role must read."
}

variable "batch_job_queue" {
  type        = string
  description = "Batch job queue ARN (for SubmitJob + env)."
}

variable "batch_job_definition_arn" {
  type        = string
  description = "Batch import job definition ARN (for IAM scoping)."
}

variable "batch_job_definition_name" {
  type        = string
  description = "Batch import job definition name (for the BATCH_JOB_DEFINITION env)."
}
