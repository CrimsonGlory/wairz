variable "name" {
  description = "Name prefix for database resources."
  type        = string
}

variable "vpc_id" {
  description = "VPC the database lives in."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR allowed to reach PostgreSQL."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets for the DB subnet group."
  type        = list(string)
}

variable "min_capacity" {
  description = "Aurora Serverless v2 minimum ACUs (0 = auto-pause; 0.5 = always-warm)."
  type        = number
  default     = 0.5
}

variable "max_capacity" {
  description = "Aurora Serverless v2 maximum ACUs."
  type        = number
  default     = 4
}

variable "engine_version" {
  description = "Aurora PostgreSQL engine version (must be a currently-available Serverless v2 version; check: aws rds describe-db-engine-versions --engine aurora-postgresql)."
  type        = string
  default     = "16.9"
}

variable "database_name" {
  description = "Initial database name."
  type        = string
  default     = "wairz"
}

variable "master_username" {
  description = "Master username."
  type        = string
  default     = "wairz"
}

variable "skip_final_snapshot" {
  description = "Skip the final snapshot on destroy (set false for prod)."
  type        = bool
  default     = true
}

variable "deletion_protection" {
  description = "Protect the cluster from deletion."
  type        = bool
  default     = false
}
