# IAM for the backend Fargate task.
#  - execution role: pull image from ECR, read secrets, ship logs
#  - task role     : the app's own permissions — submit/describe Batch jobs

data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-backend-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

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

resource "aws_iam_role" "task" {
  name               = "${var.name}-backend-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

# The backend dispatches Ghidra work to Batch.
data "aws_iam_policy_document" "task_batch" {
  statement {
    actions = ["batch:SubmitJob"]
    resources = [
      var.batch_job_queue,
      # Scope to the job-definition FAMILY, not one pinned revision. The input
      # ARN carries a ":<revision>" suffix (e.g. ...:16); the dispatcher submits
      # by NAME, which IAM authorizes against the un-revisioned family ARN — so a
      # "...:16*" resource denies it. Strip the revision, then wildcard, to match
      # the bare family ARN and every revision.
      "${replace(var.batch_job_definition_arn, "/:[0-9]+$/", "")}*",
    ]
  }
  statement {
    # TagResource is required because the dispatcher submits jobs WITH tags
    # (tag-on-create) — without it SubmitJob fails with an AccessDenied on
    # batch:TagResource. These actions don't support resource-level scoping.
    actions   = ["batch:DescribeJobs", "batch:ListJobs", "batch:TerminateJob", "batch:TagResource"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "task_batch" {
  name   = "batch-dispatch"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task_batch.json
}
