# Batch module — scale-to-zero compute for heavy Ghidra imports (and, later,
# reuse runs / the warm worker). EC2 compute environment so containers can use
# the RAM Ghidra needs (16G heap); Spot by default (jobs are idempotent —
# results cached by binary hash, so an interruption just re-runs).

# ECR repo for the Ghidra worker image. Push the backend image here (it already
# bundles Ghidra + the worker code) or a dedicated slim Ghidra image.
resource "aws_ecr_repository" "ghidra" {
  name                 = "${var.name}-ghidra"
  image_tag_mutability = "MUTABLE"
  force_delete         = true
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_security_group" "compute" {
  name_prefix = "${var.name}-batch-"
  description = "Batch compute egress (to EFS, Redis, Aurora, AWS APIs)"
  vpc_id      = var.vpc_id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-batch" }
}

resource "aws_cloudwatch_log_group" "jobs" {
  name              = "/wairz/${var.name}/batch"
  retention_in_days = var.log_retention_days
}

resource "aws_batch_compute_environment" "this" {
  compute_environment_name = "${var.name}-ghidra"
  type                     = "MANAGED"

  compute_resources {
    type                = var.use_spot ? "SPOT" : "EC2"
    allocation_strategy = var.use_spot ? "SPOT_CAPACITY_OPTIMIZED" : "BEST_FIT_PROGRESSIVE"
    bid_percentage      = var.use_spot ? var.spot_bid_percentage : null
    spot_iam_fleet_role = var.use_spot ? aws_iam_role.spot_fleet[0].arn : null

    min_vcpus     = 0
    max_vcpus     = var.max_vcpus
    instance_type = var.instance_types

    subnets            = var.private_subnet_ids
    security_group_ids = [aws_security_group.compute.id]
    instance_role      = aws_iam_instance_profile.instance.arn
  }

  # Batch uses its service-linked role automatically when service_role is unset.
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_batch_job_queue" "this" {
  name     = "${var.name}-ghidra"
  state    = "ENABLED"
  priority = 1

  compute_environment_order {
    order               = 1
    compute_environment = aws_batch_compute_environment.this.arn
  }
}

# Heavy import / full-analysis job. The command is overridden at submit time by
# the BatchDispatcher (per-binary --firmware-id/--binary-path/--sha256).
resource "aws_batch_job_definition" "import" {
  name                  = "${var.name}-ghidra-import"
  type                  = "container"
  platform_capabilities = ["EC2"]

  container_properties = jsonencode({
    image = "${aws_ecr_repository.ghidra.repository_url}:${var.image_tag}"
    # Overridden at submit; use the venv interpreter (the image bakes deps into
    # /app/.venv — bare "python" is the slim base Python without them).
    command          = ["/app/.venv/bin/python", "-m", "app.workers.run_ghidra_analysis", "--help"]
    jobRoleArn       = aws_iam_role.job.arn
    executionRoleArn = aws_iam_role.execution.arn

    resourceRequirements = [
      { type = "VCPU", value = tostring(var.job_vcpus) },
      { type = "MEMORY", value = tostring(var.job_memory_mib) },
    ]

    environment = [
      { name = "COMPUTE_BACKEND", value = "aws_batch" },
      { name = "AWS_REGION", value = var.aws_region },
      { name = "STORAGE_ROOT", value = "/data/firmware" },
      { name = "GHIDRA_PROJECT_ROOT", value = "/data/ghidra_projects" },
      { name = "REDIS_URL", value = var.redis_url },
    ]

    secrets = [
      { name = "DATABASE_URL", valueFrom = var.database_url_secret_arn },
    ]

    volumes = [
      {
        name = "firmware"
        efsVolumeConfiguration = {
          fileSystemId      = var.efs_id
          transitEncryption = "ENABLED"
          authorizationConfig = {
            accessPointId = var.efs_firmware_access_point_id
            iam           = "DISABLED"
          }
        }
      },
      {
        name = "ghidra-projects"
        efsVolumeConfiguration = {
          fileSystemId      = var.efs_id
          transitEncryption = "ENABLED"
          authorizationConfig = {
            accessPointId = var.efs_ghidra_projects_access_point_id
            iam           = "DISABLED"
          }
        }
      },
    ]

    mountPoints = [
      { sourceVolume = "firmware", containerPath = "/data/firmware", readOnly = false },
      { sourceVolume = "ghidra-projects", containerPath = "/data/ghidra_projects", readOnly = false },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.jobs.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "import"
      }
    }
  })

  retry_strategy {
    attempts = var.job_retry_attempts
    evaluate_on_exit {
      # Spot reclamation → retry; the analysis is idempotent (hash-keyed cache).
      action           = "RETRY"
      on_status_reason = "Host EC2*"
    }
    evaluate_on_exit {
      action    = "EXIT"
      on_reason = "*"
    }
  }
}
