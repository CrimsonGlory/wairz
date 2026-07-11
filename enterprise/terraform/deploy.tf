# Image & SPA delivery — build and publish as part of `terraform apply`
# (PLAN.md §4 / Phase 4 #1). Gated by var.auto_deploy_images so that:
#   * `terraform validate` and an infra-only workflow don't need Docker/Node, and
#   * CI can build/push out-of-band instead (set auto_deploy_images=false and
#     pass an explicit image_tag).
#
# Dependency note: the two ECR repos live inside the backend and batch modules
# (kept separate per design — one image, pushed to both). The build below depends
# on those repos via its triggers, but the ECS service that consumes the image
# does NOT hard-depend on the push (that would be a cycle: repo → push → service,
# all within one module). The service doesn't wait for steady state, so on a cold
# `apply` the image push and the service creation run concurrently and ECS
# converges within a minute or two once the image lands. Subsequent applies only
# re-push when the tag changes.

data "external" "image_tag" {
  count   = var.auto_deploy_images && var.image_tag == "" ? 1 : 0
  program = ["bash", "${path.module}/../scripts/image-tag.sh"]
}

locals {
  repo_root = abspath("${path.module}/../..")

  # Explicit override wins; otherwise the auto-computed git tag (when building in
  # apply); otherwise "latest" (infra-only, image managed out-of-band).
  image_tag = (
    var.image_tag != "" ? var.image_tag :
    var.auto_deploy_images ? data.external.image_tag[0].result.tag :
    "latest"
  )
}

# Build the backend image once, push it to both the backend and Ghidra repos.
resource "null_resource" "backend_image" {
  count = var.auto_deploy_images ? 1 : 0

  triggers = {
    image_tag        = local.image_tag
    backend_repo_url = module.backend.ecr_repository_url
    ghidra_repo_url  = module.batch.ecr_repository_url
  }

  provisioner "local-exec" {
    command = "${path.module}/../scripts/build-and-push-backend.sh"
    environment = {
      REPO_ROOT        = local.repo_root
      AWS_REGION       = var.aws_region
      BACKEND_REPO_URL = module.backend.ecr_repository_url
      GHIDRA_REPO_URL  = module.batch.ecr_repository_url
      IMAGE_TAG        = local.image_tag
    }
  }
}

# Build the SPA, sync it to the bucket, invalidate CloudFront. Triggered on the
# same tag (git-derived, so it also moves on any frontend change) plus the target
# identifiers, so a recreated bucket/distribution re-publishes.
resource "null_resource" "spa" {
  count = var.auto_deploy_images ? 1 : 0

  triggers = {
    image_tag       = local.image_tag
    bucket          = module.storage.spa_bucket
    distribution_id = module.frontend.distribution_id
    # Re-publish config.json when the auth wiring changes.
    auth = "${var.auth_enabled}:${var.auth_enabled ? local.oidc_issuer : ""}:${var.auth_enabled ? module.auth.client_id : ""}"
  }

  provisioner "local-exec" {
    command = "${path.module}/../scripts/deploy-spa.sh"
    environment = {
      REPO_ROOT       = local.repo_root
      AWS_REGION      = var.aws_region
      SPA_BUCKET      = module.storage.spa_bucket
      DISTRIBUTION_ID = module.frontend.distribution_id
      # Auth: deploy-spa.sh writes dist/config.json from these (no-op unless on).
      AUTH_ENABLED   = tostring(var.auth_enabled)
      OIDC_AUTHORITY = var.auth_enabled ? local.oidc_issuer : ""
      OIDC_CLIENT_ID = var.auth_enabled ? module.auth.client_id : ""
      COGNITO_DOMAIN = var.auth_enabled ? "https://${module.auth.hosted_ui_domain}.auth.${var.aws_region}.amazoncognito.com" : ""
    }
  }
}
