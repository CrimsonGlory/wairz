variable "name" {
  type        = string
  description = "Name prefix."
}

variable "domain_suffix" {
  type        = string
  default     = "auth"
  description = "Suffix for the Cognito hosted-UI domain (<name>-<suffix>.auth.<region>.amazoncognito.com). Must be globally unique."
}

variable "invite_only" {
  type        = bool
  default     = true
  description = "Admin-create-user only (no self sign-up) — appropriate for an internal team instance."
}

variable "callback_urls" {
  type        = list(string)
  default     = []
  description = "OAuth callback URLs (e.g. https://<cloudfront-domain>/oauth2/idpresponse)."
}

variable "logout_urls" {
  type        = list(string)
  default     = []
  description = "OAuth logout URLs."
}

variable "identity_providers" {
  type        = list(string)
  default     = ["COGNITO"]
  description = "Cognito-supported IdPs for the app client. Add a federated SAML/OIDC provider name (e.g. an operator's JumpCloud) to put the pool behind external SSO."
}

variable "users" {
  type = list(object({
    email = string
    name  = optional(string)
  }))
  default     = []
  description = "Users to seed into the pool (parsed from users.yaml by the root module). Each gets a Cognito-generated temporary password emailed as an invite; they set their own on first login. Ignored when federating an external IdP (those users come from the IdP)."
}
