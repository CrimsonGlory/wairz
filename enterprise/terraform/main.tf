# Root module — composes the per-concern modules under ./modules.
#
# Phase 0 establishes the provider, default tags, and shared locals. Module
# calls are added as each module is implemented (see enterprise/PLAN.md §6):
#   Phase 1 — network, storage, database, cache
#   Phase 2 — batch
#   Phase 3 — backend, frontend, auth
#
# Wiring is intentionally absent here until the referenced modules contain
# resources, so `terraform validate` passes on the Phase 0 skeleton.

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(
      {
        Project     = "wairz"
        Environment = var.environment
        ManagedBy   = "terraform"
      },
      var.tags,
    )
  }
}

# CloudFront ACM certs must live in us-east-1 regardless of the deployment
# region; this aliased provider creates the custom-domain cert there.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = merge(
      {
        Project     = "wairz"
        Environment = var.environment
        ManagedBy   = "terraform"
      },
      var.tags,
    )
  }
}

locals {
  # Canonical name prefix for all resources, e.g. "wairz-prod".
  name = "${var.name_prefix}-${var.environment}"

  # The app's public origin (custom domain if set, else the CloudFront domain).
  app_url = var.domain_name != "" ? "https://${var.domain_name}" : "https://${module.frontend.cloudfront_domain}"

  # OIDC issuer for the deployment's Cognito user pool. An operator can override
  # the backend's view of this to point at another issuer, but by default the
  # SPA logs in to this pool (which can itself federate an external IdP).
  oidc_issuer = "https://cognito-idp.${var.aws_region}.amazonaws.com/${module.auth.user_pool_id}"

  # Cognito OAuth redirect/sign-out URLs. Keyed off the *input* domain_name (not
  # the frontend output) to avoid a backend→auth→frontend→backend cycle; a
  # localhost entry keeps the client valid when no domain is set and helps local
  # SPA dev. auth_enabled requires a real domain (precondition below).
  app_callback_urls = compact([
    var.domain_name != "" ? "https://${var.domain_name}/callback" : "",
    "http://localhost:3000/callback",
    # Loopback redirect for the CLI token helper's Authorization Code + PKCE
    # login (enterprise/scripts/wairz_mcp_token.py). Cognito requires the exact
    # URI to be pre-registered.
    "http://localhost:${var.mcp_cli_redirect_port}/callback",
  ])
  app_logout_urls = compact([
    var.domain_name != "" ? "https://${var.domain_name}/" : "",
    "http://localhost:3000/",
  ])

  # Optional declarative user seeding. Parse users.yaml (path relative to the
  # terraform dir unless absolute) only when auth is on — seeding Cognito users
  # for a pool nobody logs into would just send stray invite emails.
  users_file_path = startswith(var.users_file, "/") ? var.users_file : "${path.module}/${var.users_file}"
  seed_users = (var.auth_enabled && fileexists(local.users_file_path)
    ? yamldecode(file(local.users_file_path))
  : [])
}

# auth_enabled needs a stable redirect domain.
resource "terraform_data" "auth_requires_domain" {
  lifecycle {
    precondition {
      condition     = !var.auth_enabled || var.domain_name != ""
      error_message = "auth_enabled requires domain_name (the OIDC redirect URI must be on a stable custom domain)."
    }
  }
}

# ---------------------------------------------------------------------------
# Module wiring. Phase 1 modules (network, storage, database, cache) are live;
# later-phase modules stay commented until they land (PLAN.md §6).
# ---------------------------------------------------------------------------

module "network" {
  source             = "./modules/network"
  name               = local.name
  aws_region         = var.aws_region
  vpc_cidr           = var.vpc_cidr
  create_nat_gateway = var.create_nat_gateway
  # With auth on and no NAT, the backend needs the Cognito JWKS endpoint
  # reachable privately to validate tokens.
  extra_interface_endpoints = var.auth_enabled && !var.create_nat_gateway ? ["cognito-idp"] : []
}

module "storage" {
  source             = "./modules/storage"
  name               = local.name
  vpc_id             = module.network.vpc_id
  vpc_cidr           = module.network.vpc_cidr
  private_subnet_ids = module.network.private_subnet_ids
}

module "database" {
  source             = "./modules/database"
  name               = local.name
  vpc_id             = module.network.vpc_id
  vpc_cidr           = module.network.vpc_cidr
  private_subnet_ids = module.network.private_subnet_ids
  min_capacity       = var.aurora_min_capacity
  max_capacity       = var.aurora_max_capacity
}

module "cache" {
  source             = "./modules/cache"
  name               = local.name
  vpc_id             = module.network.vpc_id
  vpc_cidr           = module.network.vpc_cidr
  private_subnet_ids = module.network.private_subnet_ids
  node_type          = var.redis_node_type
}

module "batch" {
  source     = "./modules/batch"
  name       = local.name
  aws_region = var.aws_region
  vpc_id     = module.network.vpc_id
  image_tag  = local.image_tag

  private_subnet_ids = module.network.private_subnet_ids
  max_vcpus          = var.batch_max_vcpus
  use_spot           = var.batch_use_spot

  efs_id                              = module.storage.efs_id
  efs_firmware_access_point_id        = module.storage.efs_firmware_access_point_id
  efs_ghidra_projects_access_point_id = module.storage.efs_ghidra_projects_access_point_id
  redis_url                           = module.cache.redis_url
  database_url_secret_arn             = module.database.database_url_secret_arn
  secret_arns                         = [module.database.database_url_secret_arn]
}

module "backend" {
  source     = "./modules/backend"
  name       = local.name
  aws_region = var.aws_region
  vpc_id     = module.network.vpc_id
  image_tag  = local.image_tag

  public_subnet_ids  = module.network.public_subnet_ids
  private_subnet_ids = module.network.private_subnet_ids

  efs_id                              = module.storage.efs_id
  efs_firmware_access_point_id        = module.storage.efs_firmware_access_point_id
  efs_ghidra_projects_access_point_id = module.storage.efs_ghidra_projects_access_point_id
  redis_url                           = module.cache.redis_url
  database_url_secret_arn             = module.database.database_url_secret_arn
  secret_arns                         = [module.database.database_url_secret_arn]

  batch_job_queue           = module.batch.job_queue_arn
  batch_job_definition_arn  = module.batch.import_job_definition_arn
  batch_job_definition_name = module.batch.import_job_definition_name

  max_upload_size_mb          = var.max_upload_size_mb
  certificate_arn             = var.alb_certificate_arn
  batch_max_jobs_per_firmware = var.batch_max_jobs_per_firmware

  auth_enabled  = var.auth_enabled
  oidc_issuer   = var.auth_enabled ? local.oidc_issuer : ""
  oidc_audience = var.auth_enabled ? module.auth.client_id : ""

  mcp_http_enabled = var.mcp_http_enabled
}

module "frontend" {
  source = "./modules/frontend"
  name   = local.name

  spa_bucket                      = module.storage.spa_bucket
  spa_bucket_arn                  = module.storage.spa_bucket_arn
  spa_bucket_regional_domain_name = module.storage.spa_bucket_regional_domain_name
  alb_dns_name                    = module.backend.alb_dns_name

  aliases             = var.domain_name != "" ? [var.domain_name] : []
  acm_certificate_arn = var.domain_name != "" ? aws_acm_certificate_validation.cf[0].certificate_arn : ""
  mcp_enabled         = var.mcp_http_enabled
}

module "auth" {
  source        = "./modules/auth"
  name          = local.name
  domain_suffix = var.cognito_domain_suffix
  callback_urls = local.app_callback_urls
  logout_urls   = local.app_logout_urls
  users         = local.seed_users
}

module "observability" {
  source      = "./modules/observability"
  name        = local.name
  aws_region  = var.aws_region
  alarm_email = var.alarm_email

  ecs_cluster_name        = module.backend.cluster_name
  ecs_service_name        = module.backend.service_name
  alb_arn_suffix          = module.backend.alb_arn_suffix
  target_group_arn_suffix = module.backend.target_group_arn_suffix
  backend_log_group_name  = module.backend.log_group_name

  aurora_cluster_identifier = module.database.cluster_identifier
  redis_cache_cluster_id    = module.cache.cache_cluster_id
}
