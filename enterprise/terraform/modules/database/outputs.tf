output "cluster_endpoint" {
  value = aws_rds_cluster.this.endpoint
}

output "reader_endpoint" {
  value = aws_rds_cluster.this.reader_endpoint
}

output "database_url_secret_arn" {
  description = "Secrets Manager ARN holding the full asyncpg DATABASE_URL."
  value       = aws_secretsmanager_secret.database_url.arn
}

output "security_group_id" {
  value = aws_security_group.db.id
}

output "cluster_identifier" {
  description = "Aurora cluster id (CloudWatch DBClusterIdentifier dimension)."
  value       = aws_rds_cluster.this.cluster_identifier
}
