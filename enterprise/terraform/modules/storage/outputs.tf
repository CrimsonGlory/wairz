output "efs_id" {
  value = aws_efs_file_system.this.id
}

output "efs_firmware_access_point_id" {
  value = aws_efs_access_point.firmware.id
}

output "efs_firmware_access_point_arn" {
  value = aws_efs_access_point.firmware.arn
}

output "efs_ghidra_projects_access_point_id" {
  value = aws_efs_access_point.ghidra_projects.id
}

output "efs_ghidra_projects_access_point_arn" {
  value = aws_efs_access_point.ghidra_projects.arn
}

output "spa_bucket" {
  value = aws_s3_bucket.spa.id
}

output "spa_bucket_arn" {
  value = aws_s3_bucket.spa.arn
}

output "spa_bucket_regional_domain_name" {
  value = aws_s3_bucket.spa.bucket_regional_domain_name
}
