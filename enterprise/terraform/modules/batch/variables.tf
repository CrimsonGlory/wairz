variable "name" {
  description = "Name prefix for Batch resources."
  type        = string
}

variable "aws_region" {
  description = "AWS region (for log config)."
  type        = string
}

variable "vpc_id" {
  description = "VPC the compute environment runs in."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets for Batch compute (must reach EFS/Redis/Aurora/ECR)."
  type        = list(string)
}

variable "max_vcpus" {
  description = "Ceiling on compute-environment vCPUs (cost guardrail)."
  type        = number
  default     = 16
}

variable "use_spot" {
  description = "Run on Spot (cheaper; jobs are idempotent so interruptions are safe)."
  type        = bool
  default     = true
}

variable "spot_bid_percentage" {
  description = "Max Spot price as % of on-demand."
  type        = number
  default     = 100
}

variable "instance_types" {
  description = "Instance types/families Batch may launch. 'optimal' = M/C/R families; Ghidra's 16G heap wants memory, so include r-family for big binaries."
  type        = list(string)
  default     = ["optimal"]
}

variable "job_vcpus" {
  description = "vCPUs per Ghidra import job."
  type        = number
  default     = 4
}

variable "job_memory_mib" {
  description = "Memory (MiB) per import job. Must exceed Ghidra's heap (MAXMEM=16G) — default 30 GiB."
  type        = number
  default     = 30720
}

variable "job_retry_attempts" {
  description = "Batch job retry attempts (covers Spot reclamation)."
  type        = number
  default     = 2
}

variable "image_tag" {
  description = "Tag of the Ghidra worker image in the module's ECR repo."
  type        = string
  default     = "latest"
}

variable "log_retention_days" {
  description = "CloudWatch log retention for Batch jobs."
  type        = number
  default     = 30
}

# --- Wired from other modules ----------------------------------------------
variable "efs_id" {
  type        = string
  description = "Shared EFS filesystem id."
}

variable "efs_firmware_access_point_id" {
  type        = string
  description = "EFS access point for the firmware tree."
}

variable "efs_ghidra_projects_access_point_id" {
  type        = string
  description = "EFS access point for the Ghidra project store."
}

variable "redis_url" {
  type        = string
  description = "Redis URL (for the distributed analysis lock)."
}

variable "database_url_secret_arn" {
  type        = string
  description = "Secrets Manager ARN holding the asyncpg DATABASE_URL."
}

variable "secret_arns" {
  type        = list(string)
  description = "All secret ARNs the execution role must read (e.g. DATABASE_URL)."
  default     = []
}
