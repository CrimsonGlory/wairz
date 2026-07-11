# Auth module — Cognito user pool for the shared multi-user instance.
#
# Creates the pool, an app client, and a hosted-UI domain. Wiring auth onto the
# ALB (authenticate-cognito listener action) requires an HTTPS listener + ACM
# cert; alternatively enforce auth at the app/CloudFront layer. See PLAN.md §7.

resource "aws_cognito_user_pool" "this" {
  name = "${var.name}-users"

  admin_create_user_config {
    allow_admin_create_user_only = var.invite_only
  }

  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }

  auto_verified_attributes = ["email"]

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }
}

resource "aws_cognito_user_pool_client" "this" {
  name         = "${var.name}-web"
  user_pool_id = aws_cognito_user_pool.this.id

  # Public SPA client: Authorization Code + PKCE, no client secret (a browser
  # can't keep one). PKCE secures the code exchange instead.
  generate_secret                      = false
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  allowed_oauth_flows_user_pool_client = true
  # COGNITO today; an operator federates their IdP (JumpCloud/Okta/…) by adding
  # a SAML/OIDC provider to the pool and listing it here. The SPA login flow is
  # unchanged — Cognito brokers to the IdP.
  supported_identity_providers = var.identity_providers

  callback_urls = var.callback_urls
  logout_urls   = var.logout_urls

  # Don't reveal whether an account exists on failed auth; allow token
  # revocation on sign-out.
  prevent_user_existence_errors = "ENABLED"
  enable_token_revocation       = true

  explicit_auth_flows = [
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]
}

resource "aws_cognito_user_pool_domain" "this" {
  domain       = "${var.name}-${var.domain_suffix}"
  user_pool_id = aws_cognito_user_pool.this.id
}

# Seed users declaratively from users.yaml (root module parses the file). Each
# user is created in the standard admin-invite flow: Cognito generates a
# temporary password and emails an invite (FORCE_CHANGE_PASSWORD), and the user
# sets their own password on first login — Terraform never holds a password.
# Editing users.yaml + re-applying adds/removes accounts; removing a user here
# deletes the Cognito account. Keyed by email so the set is stable across applies.
resource "aws_cognito_user" "seed" {
  for_each = { for u in var.users : lower(u.email) => u }

  user_pool_id = aws_cognito_user_pool.this.id
  username     = each.value.email

  attributes = merge(
    {
      email          = each.value.email
      email_verified = "true"
    },
    each.value.name != null ? { name = each.value.name } : {},
  )

  desired_delivery_mediums = ["EMAIL"]

  # Don't churn the temporary password on every apply (it's regenerated server
  # side and not tracked here); leave existing accounts alone once created.
  lifecycle {
    ignore_changes = [temporary_password]
  }
}
