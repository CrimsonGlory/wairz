output "dashboard_name" {
  description = "CloudWatch dashboard name (see app_url region console)."
  value       = aws_cloudwatch_dashboard.this.dashboard_name
}

output "alarm_topic_arn" {
  description = "SNS topic alarms publish to (subscribe more endpoints as needed)."
  value       = aws_sns_topic.alarms.arn
}
