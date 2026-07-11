output "user_pool_id" {
  value = aws_cognito_user_pool.this.id
}

output "user_pool_arn" {
  value = aws_cognito_user_pool.this.arn
}

output "client_id" {
  value = aws_cognito_user_pool_client.this.id
}

output "hosted_ui_domain" {
  value = aws_cognito_user_pool_domain.this.domain
}

output "seeded_user_emails" {
  description = "Emails seeded into the pool from users.yaml."
  value       = sort([for u in aws_cognito_user.seed : u.username])
}
