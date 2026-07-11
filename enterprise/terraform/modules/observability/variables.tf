variable "name" {
  type        = string
  description = "Resource name prefix (e.g. wairz-prod)."
}

variable "aws_region" {
  type        = string
  description = "Region the dashboard renders metrics for."
}

variable "alarm_email" {
  type        = string
  default     = ""
  description = "If set, subscribes this address to the alarm SNS topic. Empty = topic created (alarm actions still fire) but no subscription."
}

# --- Metric dimensions (from the other modules) -----------------------------
variable "ecs_cluster_name" { type = string }
variable "ecs_service_name" { type = string }
variable "alb_arn_suffix" { type = string }
variable "target_group_arn_suffix" { type = string }
variable "aurora_cluster_identifier" { type = string }
variable "redis_cache_cluster_id" { type = string }
variable "backend_log_group_name" { type = string }

# --- Alarm thresholds (sane defaults; override per environment) --------------
variable "cpu_high_percent" {
  type        = number
  default     = 85
  description = "ECS service + Aurora CPU alarm threshold (%)."
}

variable "alb_5xx_threshold" {
  type        = number
  default     = 10
  description = "Target 5XX responses over the eval window before alarming."
}

variable "latency_threshold_seconds" {
  type        = number
  default     = 2
  description = "ALB average target response time alarm threshold (s)."
}

variable "redis_memory_high_percent" {
  type        = number
  default     = 85
  description = "ElastiCache DatabaseMemoryUsagePercentage alarm threshold (%)."
}
