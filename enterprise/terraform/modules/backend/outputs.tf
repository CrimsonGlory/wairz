output "alb_dns_name" {
  description = "ALB DNS name (CloudFront API origin)."
  value       = aws_lb.this.dns_name
}

output "alb_zone_id" {
  value = aws_lb.this.zone_id
}

output "ecr_repository_url" {
  description = "Push the backend image here (also reused as the Batch Ghidra image)."
  value       = aws_ecr_repository.backend.repository_url
}

output "cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "service_name" {
  value = aws_ecs_service.this.name
}

output "service_security_group_id" {
  value = aws_security_group.service.id
}

# CloudWatch dimensions / log source for the observability module.
output "alb_arn_suffix" {
  description = "ALB ARN suffix (CloudWatch LoadBalancer dimension)."
  value       = aws_lb.this.arn_suffix
}

output "target_group_arn_suffix" {
  description = "Target group ARN suffix (CloudWatch TargetGroup dimension)."
  value       = aws_lb_target_group.this.arn_suffix
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.backend.name
}
