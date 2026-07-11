# Backend module — FastAPI on ECS Fargate behind an ALB. Stateless and
# autoscaled; all state lives in Aurora / Redis / EFS. Heavy Ghidra work is
# dispatched to Batch (COMPUTE_BACKEND=aws_batch), so this task stays small.

resource "aws_ecr_repository" "backend" {
  name                 = "${var.name}-backend"
  image_tag_mutability = "MUTABLE"
  force_delete         = true
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_cloudwatch_log_group" "backend" {
  name              = "/wairz/${var.name}/backend"
  retention_in_days = var.log_retention_days
}

resource "aws_ecs_cluster" "this" {
  name = "${var.name}-backend"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# --- Security groups --------------------------------------------------------
# Only CloudFront may reach the ALB: ingress is restricted to AWS's managed
# CloudFront origin-facing prefix list, so the ALB can't be hit directly over
# the internet (which would bypass CloudFront's TLS/custom-domain and any WAF).
# Defense in depth alongside the app's bearer-token auth.
data "aws_ec2_managed_prefix_list" "cloudfront" {
  name = "com.amazonaws.global.cloudfront.origin-facing"
}

resource "aws_security_group" "alb" {
  name_prefix = "${var.name}-alb-"
  description = "CloudFront-only HTTP(S) to the ALB"
  vpc_id      = var.vpc_id

  ingress {
    description     = "HTTP from CloudFront"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront.id]
  }
  dynamic "ingress" {
    for_each = var.certificate_arn == "" ? [] : [1]
    content {
      description     = "HTTPS from CloudFront"
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront.id]
    }
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-alb" }

  # The CloudFront prefix list expands to ~55 entries, each counting as a rule
  # against the per-SG quota (default 60). HTTP-only (the default, TLS at the
  # edge) fits; enabling the optional ALB HTTPS listener too may need the quota
  # raised.
}

resource "aws_security_group" "service" {
  name_prefix = "${var.name}-svc-"
  description = "ALB to backend task on the app port"
  vpc_id      = var.vpc_id

  ingress {
    description     = "From ALB"
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  # MCP sidecar port (Phase 5) — only when the sidecar is enabled.
  dynamic "ingress" {
    for_each = var.mcp_http_enabled ? [1] : []
    content {
      description     = "MCP sidecar from ALB"
      from_port       = var.mcp_container_port
      to_port         = var.mcp_container_port
      protocol        = "tcp"
      security_groups = [aws_security_group.alb.id]
    }
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-svc" }
}

# --- ALB --------------------------------------------------------------------
resource "aws_lb" "this" {
  name               = "${var.name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids
  idle_timeout       = 4000 # long-lived websockets (xterm, live polling)
}

resource "aws_lb_target_group" "this" {
  name        = "${var.name}-tg"
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = var.health_check_path
    matcher             = "200-399"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 5
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

# Optional HTTPS listener (when an ACM cert is supplied). For ALB-level Cognito
# auth, add an authenticate-cognito action here — requires this HTTPS listener.
resource "aws_lb_listener" "https" {
  count             = var.certificate_arn == "" ? 0 : 1
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

# --- MCP sidecar target group + routing (Phase 5) ---------------------------
# /mcp* is forwarded to the MCP sidecar container; everything else falls through
# to the backend (default action). The sidecar serves an unauthenticated health
# path for the target-group check (the MCP endpoint itself never 200s a bare GET).
resource "aws_lb_target_group" "mcp" {
  count       = var.mcp_http_enabled ? 1 : 0
  name        = "${var.name}-mcp-tg"
  port        = var.mcp_container_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  # Tolerant on purpose: the MCP sidecar is a single-process event loop, and a
  # heavy in-process analysis tool can block it for a while. A trigger-happy
  # check would mark the target unhealthy and make ECS reap the whole task —
  # killing the user's live MCP session. ~5 min of grace before that happens.
  health_check {
    path                = var.mcp_health_path
    matcher             = "200"
    interval            = 30
    timeout             = 15
    healthy_threshold   = 2
    unhealthy_threshold = 10
  }
}

resource "aws_lb_listener_rule" "mcp_http" {
  count        = var.mcp_http_enabled ? 1 : 0
  listener_arn = aws_lb_listener.http.arn
  priority     = 10
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.mcp[0].arn
  }
  condition {
    path_pattern {
      values = ["/mcp", "/mcp/*"]
    }
  }
}

resource "aws_lb_listener_rule" "mcp_https" {
  count        = var.mcp_http_enabled && var.certificate_arn != "" ? 1 : 0
  listener_arn = aws_lb_listener.https[0].arn
  priority     = 10
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.mcp[0].arn
  }
  condition {
    path_pattern {
      values = ["/mcp", "/mcp/*"]
    }
  }
}

# --- Task definition + service ----------------------------------------------
locals {
  efs_volumes = {
    firmware        = { ap = var.efs_firmware_access_point_id, path = "/data/firmware" }
    ghidra-projects = { ap = var.efs_ghidra_projects_access_point_id, path = "/data/ghidra_projects" }
  }

  # Shared by the backend container and the MCP sidecar — both talk to the same
  # DB/Redis/Batch/EFS and need the same OIDC + compute config.
  container_environment = [
    { name = "COMPUTE_BACKEND", value = "aws_batch" },
    { name = "AWS_REGION", value = var.aws_region },
    { name = "STORAGE_ROOT", value = "/data/firmware" },
    { name = "GHIDRA_PROJECT_ROOT", value = "/data/ghidra_projects" },
    { name = "REDIS_URL", value = var.redis_url },
    { name = "BATCH_JOB_QUEUE", value = var.batch_job_queue },
    { name = "BATCH_JOB_DEFINITION", value = var.batch_job_definition_name },
    { name = "BATCH_MAX_JOBS_PER_FIRMWARE", value = tostring(var.batch_max_jobs_per_firmware) },
    { name = "MAX_UPLOAD_SIZE_MB", value = tostring(var.max_upload_size_mb) },
    # OIDC auth (no-op unless AUTH_ENABLED=true).
    { name = "AUTH_ENABLED", value = tostring(var.auth_enabled) },
    { name = "OIDC_ISSUER", value = var.oidc_issuer },
    { name = "OIDC_AUDIENCE", value = var.oidc_audience },
    # Host/origin guard: behind CloudFront/ALB (+ Cognito) the Host varies, so
    # default to permissive. Tighten to the specific CloudFront/custom domain
    # in production if you want DNS-rebinding protection at the app layer too.
    { name = "ALLOWED_HOSTS", value = var.allowed_hosts },
    { name = "ALLOWED_ORIGINS", value = var.allowed_origins },
  ]

  container_secrets = [
    { name = "DATABASE_URL", valueFrom = var.database_url_secret_arn },
  ]

  container_mount_points = [
    for k, v in local.efs_volumes : { sourceVolume = k, containerPath = v.path, readOnly = false }
  ]

  backend_container = {
    name         = "backend"
    image        = "${aws_ecr_repository.backend.repository_url}:${var.image_tag}"
    essential    = true
    portMappings = [{ containerPort = var.container_port, protocol = "tcp" }]

    # Run from the image's prebuilt venv directly. The image's default CMD uses
    # `uv run`, which re-resolves the project against pypi.org at startup — that
    # fails in a private subnet with no internet egress (VPC endpoints reach AWS
    # services only). Invoking the venv binaries avoids any network at boot.
    command = ["sh", "-c",
      "/app/.venv/bin/alembic upgrade head && exec /app/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port ${var.container_port}"
    ]

    environment = local.container_environment
    secrets     = local.container_secrets
    mountPoints = local.container_mount_points
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.backend.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "backend"
      }
    }
  }

  # MCP sidecar (Phase 5): the same image, run as the Streamable HTTP MCP server.
  # essential=false so an MCP fault can't take down the REST API / migrations;
  # the venv console script avoids any pypi re-resolution at boot.
  mcp_container = {
    name         = "mcp"
    image        = "${aws_ecr_repository.backend.repository_url}:${var.image_tag}"
    essential    = false
    portMappings = [{ containerPort = var.mcp_container_port, protocol = "tcp" }]

    command = ["/app/.venv/bin/wairz-mcp", "--transport", "http",
      "--host", "0.0.0.0", "--port", tostring(var.mcp_container_port),
      "--path", "/mcp"
    ]

    environment = local.container_environment
    secrets     = local.container_secrets
    mountPoints = local.container_mount_points
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.backend.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "mcp"
      }
    }
  }

  containers = var.mcp_http_enabled ? [local.backend_container, local.mcp_container] : [local.backend_container]

  service_load_balancers = concat(
    [{ tg = aws_lb_target_group.this.arn, container = "backend", port = var.container_port }],
    var.mcp_http_enabled ? [{ tg = aws_lb_target_group.mcp[0].arn, container = "mcp", port = var.mcp_container_port }] : [],
  )
}

resource "aws_ecs_task_definition" "this" {
  family                   = "${var.name}-backend"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  dynamic "volume" {
    for_each = local.efs_volumes
    content {
      name = volume.key
      efs_volume_configuration {
        file_system_id     = var.efs_id
        transit_encryption = "ENABLED"
        authorization_config {
          access_point_id = volume.value.ap
          iam             = "DISABLED"
        }
      }
    }
  }

  container_definitions = jsonencode(local.containers)
}

resource "aws_ecs_service" "this" {
  name                              = "${var.name}-backend"
  cluster                           = aws_ecs_cluster.this.id
  task_definition                   = aws_ecs_task_definition.this.arn
  desired_count                     = var.desired_count
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 120 # let migrations + uvicorn boot before ELB checks count

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.service.id]
    assign_public_ip = false
  }

  dynamic "load_balancer" {
    for_each = local.service_load_balancers
    content {
      target_group_arn = load_balancer.value.tg
      container_name   = load_balancer.value.container
      container_port   = load_balancer.value.port
    }
  }

  # Migrations run on container start (alembic upgrade head in the image CMD).
  depends_on = [aws_lb_listener.http, aws_lb_listener_rule.mcp_http]
}

# --- Autoscaling on CPU -----------------------------------------------------
resource "aws_appautoscaling_target" "this" {
  max_capacity       = var.max_count
  min_capacity       = var.desired_count
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.this.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${var.name}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.this.resource_id
  scalable_dimension = aws_appautoscaling_target.this.scalable_dimension
  service_namespace  = aws_appautoscaling_target.this.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value = var.cpu_target_percent
  }
}

# Allow the backend task to mount EFS (NFS) — the EFS SG allows the VPC CIDR,
# which already covers the private subnets, so no extra rule is needed here.
