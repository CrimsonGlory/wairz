output "job_queue_arn" {
  value = aws_batch_job_queue.this.arn
}

output "job_queue_name" {
  value = aws_batch_job_queue.this.name
}

output "import_job_definition_arn" {
  value = aws_batch_job_definition.import.arn
}

output "import_job_definition_name" {
  value = aws_batch_job_definition.import.name
}

output "ecr_repository_url" {
  description = "Push the Ghidra worker image here."
  value       = aws_ecr_repository.ghidra.repository_url
}

output "compute_security_group_id" {
  value = aws_security_group.compute.id
}
