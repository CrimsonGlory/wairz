# Storage module — EFS for shared POSIX state (firmware + Ghidra project store)
# and the S3 bucket that serves the SPA (CloudFront origin, Phase 3).
#
# Firmware MUST stay a real POSIX path (the sandbox does realpath checks), so it
# lives on EFS, not S3 — see PLAN.md fact #8.

# --- EFS --------------------------------------------------------------------
resource "aws_efs_file_system" "this" {
  creation_token   = "${var.name}-efs"
  encrypted        = true
  throughput_mode  = var.efs_throughput_mode
  performance_mode = "generalPurpose"

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }
  tags = { Name = "${var.name}-efs" }
}

resource "aws_security_group" "efs" {
  name_prefix = "${var.name}-efs-"
  description = "NFS (2049) to EFS from within the VPC"
  vpc_id      = var.vpc_id

  ingress {
    description = "NFS from VPC"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-efs" }
}

resource "aws_efs_mount_target" "this" {
  count           = length(var.private_subnet_ids)
  file_system_id  = aws_efs_file_system.this.id
  subnet_id       = var.private_subnet_ids[count.index]
  security_groups = [aws_security_group.efs.id]
}

# Access point for the firmware tree (mounted at STORAGE_ROOT).
resource "aws_efs_access_point" "firmware" {
  file_system_id = aws_efs_file_system.this.id
  posix_user {
    uid = var.posix_uid
    gid = var.posix_gid
  }
  root_directory {
    path = "/firmware"
    creation_info {
      owner_uid   = var.posix_uid
      owner_gid   = var.posix_gid
      permissions = "0755"
    }
  }
  tags = { Name = "${var.name}-firmware" }
}

# Access point for the persistent Ghidra project store (mounted at
# GHIDRA_PROJECT_ROOT). Shared by the backend and the Ghidra Batch jobs.
resource "aws_efs_access_point" "ghidra_projects" {
  file_system_id = aws_efs_file_system.this.id
  posix_user {
    uid = var.posix_uid
    gid = var.posix_gid
  }
  root_directory {
    path = "/ghidra_projects"
    creation_info {
      owner_uid   = var.posix_uid
      owner_gid   = var.posix_gid
      permissions = "0755"
    }
  }
  tags = { Name = "${var.name}-ghidra-projects" }
}

# --- S3 (SPA static assets) -------------------------------------------------
resource "aws_s3_bucket" "spa" {
  bucket_prefix = "${var.name}-spa-"
  tags          = { Name = "${var.name}-spa" }

  # The SPA bundle is published into this bucket (terraform-managed, derived
  # artifacts — not user data). Let `terraform destroy` empty it; without this,
  # teardown fails with BucketNotEmpty once the SPA has been synced.
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "spa" {
  bucket                  = aws_s3_bucket.spa.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "spa" {
  bucket = aws_s3_bucket.spa.id
  versioning_configuration {
    status = "Suspended"
  }
}
