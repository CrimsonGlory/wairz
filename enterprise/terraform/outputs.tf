# Root outputs. Populated as modules land (see PLAN.md §6).

# --- Phase 1: state backbone ------------------------------------------------
output "vpc_id" {
  description = "VPC id."
  value       = module.network.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet ids (EFS/DB/cache/Batch live here)."
  value       = module.network.private_subnet_ids
}

output "efs_id" {
  description = "Shared EFS filesystem id."
  value       = module.storage.efs_id
}

output "database_url_secret_arn" {
  description = "Secrets Manager ARN holding the asyncpg DATABASE_URL."
  value       = module.database.database_url_secret_arn
}

output "redis_url" {
  description = "Redis URL for the backend REDIS_URL setting."
  value       = module.cache.redis_url
}

output "spa_bucket" {
  description = "S3 bucket serving the SPA (CloudFront origin, Phase 3)."
  value       = module.storage.spa_bucket
}

# --- Phase 2b: Ghidra on Batch ----------------------------------------------
output "batch_job_queue" {
  description = "AWS Batch job queue for Ghidra jobs (BATCH_JOB_QUEUE)."
  value       = module.batch.job_queue_arn
}

output "batch_import_job_definition" {
  description = "Batch job definition for heavy Ghidra imports (BATCH_JOB_DEFINITION)."
  value       = module.batch.import_job_definition_name
}

output "ghidra_ecr_repository_url" {
  description = "Push the Ghidra worker image here before first analysis."
  value       = module.batch.ecr_repository_url
}

# --- Phase 3: serving layer -------------------------------------------------
output "app_url" {
  description = "URL serving the Wairz SPA + API (custom domain if set, else CloudFront)."
  value       = local.app_url
}

output "cloudfront_url" {
  description = "Always the underlying CloudFront URL (useful while DNS/cert propagate)."
  value       = "https://${module.frontend.cloudfront_domain}"
}

output "alb_dns_name" {
  description = "Backend ALB DNS name (CloudFront API origin)."
  value       = module.backend.alb_dns_name
}

output "backend_ecr_repository_url" {
  description = "Push the backend image here (also reused as the Batch Ghidra image)."
  value       = module.backend.ecr_repository_url
}

output "image_tag" {
  description = "Container image tag deployed to ECS + Batch (auto-derived from git unless overridden)."
  value       = local.image_tag
}

output "cognito_user_pool_id" {
  value = module.auth.user_pool_id
}

output "cognito_hosted_ui_domain" {
  value = module.auth.hosted_ui_domain
}

output "cognito_app_client_id" {
  description = "Cognito app client id (the SPA's OIDC client / token audience)."
  value       = module.auth.client_id
}

output "auth_enabled" {
  description = "Whether OIDC login is enforced on this deployment."
  value       = var.auth_enabled
}

output "cognito_seeded_users" {
  description = "Emails seeded into the Cognito pool from users.yaml (each emailed an invite on creation)."
  value       = module.auth.seeded_user_emails
}

output "mcp_url" {
  description = "Remote MCP (Streamable HTTP) endpoint, when enabled — connect Claude here with a Cognito bearer."
  value       = var.mcp_http_enabled ? "${local.app_url}/mcp" : ""
}

# --- Phase 4: observability -------------------------------------------------
output "dashboard_name" {
  description = "CloudWatch dashboard (Console → CloudWatch → Dashboards, in aws_region)."
  value       = module.observability.dashboard_name
}

output "alarm_topic_arn" {
  description = "SNS topic CloudWatch alarms publish to."
  value       = module.observability.alarm_topic_arn
}

# output "app_url" {
#   description = "CloudFront URL serving the Wairz SPA."
#   value       = module.frontend.cloudfront_domain
# }

# output "alb_dns_name" {
#   description = "ALB DNS name (backend origin)."
#   value       = module.backend.alb_dns_name
# }

# output "batch_job_queue" {
#   description = "AWS Batch job queue for Ghidra jobs."
#   value       = module.batch.job_queue_arn
# }
