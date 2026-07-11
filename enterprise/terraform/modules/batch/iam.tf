# IAM roles for AWS Batch on EC2.
#
#  - instance role : the EC2 hosts Batch launches (ECS agent permissions)
#  - spot fleet role: lets Batch request Spot capacity (Spot compute envs only)
#  - execution role : pulls the image from ECR, injects secrets, ships logs
#  - job role       : the worker's own AWS permissions (read the DB secret)

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# --- EC2 instance role ------------------------------------------------------
resource "aws_iam_role" "instance" {
  name               = "${var.name}-batch-instance"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "instance_ecs" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.name}-batch-instance"
  role = aws_iam_role.instance.name
}

# --- Spot fleet role (only used when use_spot = true) -----------------------
data "aws_iam_policy_document" "spot_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["spotfleet.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "spot_fleet" {
  count              = var.use_spot ? 1 : 0
  name               = "${var.name}-batch-spotfleet"
  assume_role_policy = data.aws_iam_policy_document.spot_assume.json
}

resource "aws_iam_role_policy_attachment" "spot_fleet" {
  count      = var.use_spot ? 1 : 0
  role       = aws_iam_role.spot_fleet[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2SpotFleetTaggingRole"
}

# --- Task execution role ----------------------------------------------------
resource "aws_iam_role" "execution" {
  name               = "${var.name}-batch-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Let the execution role read the secrets injected into the container.
data "aws_iam_policy_document" "execution_secrets" {
  count = length(var.secret_arns) > 0 ? 1 : 0
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = var.secret_arns
  }
}

resource "aws_iam_role_policy" "execution_secrets" {
  count  = length(var.secret_arns) > 0 ? 1 : 0
  name   = "secrets-read"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution_secrets[0].json
}

# --- Job (task) role --------------------------------------------------------
resource "aws_iam_role" "job" {
  name               = "${var.name}-batch-job"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}
