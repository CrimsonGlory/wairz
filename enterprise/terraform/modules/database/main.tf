# Database module — Aurora Serverless v2 (PostgreSQL). Scales toward zero at
# rest (min_capacity), bursts during analysis writes. The full asyncpg
# DATABASE_URL is stored in Secrets Manager so the backend pulls one secret.

resource "random_password" "db" {
  length  = 32
  special = false # keep the URL clean (no @ / : / % to escape)
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.name}-db"
  subnet_ids = var.private_subnet_ids
  tags       = { Name = "${var.name}-db" }
}

resource "aws_security_group" "db" {
  name_prefix = "${var.name}-db-"
  description = "PostgreSQL (5432) from within the VPC"
  vpc_id      = var.vpc_id

  ingress {
    description = "PostgreSQL from VPC"
    from_port   = 5432
    to_port     = 5432
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
  tags = { Name = "${var.name}-db" }
}

resource "aws_rds_cluster" "this" {
  cluster_identifier     = "${var.name}-aurora"
  engine                 = "aurora-postgresql"
  engine_mode            = "provisioned" # required for Serverless v2 scaling
  engine_version         = var.engine_version
  database_name          = var.database_name
  master_username        = var.master_username
  master_password        = random_password.db.result
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.db.id]
  storage_encrypted      = true

  skip_final_snapshot       = var.skip_final_snapshot
  final_snapshot_identifier = var.skip_final_snapshot ? null : "${var.name}-aurora-final"
  deletion_protection       = var.deletion_protection

  serverlessv2_scaling_configuration {
    min_capacity = var.min_capacity
    max_capacity = var.max_capacity
  }
}

resource "aws_rds_cluster_instance" "this" {
  identifier         = "${var.name}-aurora-1"
  cluster_identifier = aws_rds_cluster.this.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.this.engine
  engine_version     = aws_rds_cluster.this.engine_version
}

# --- Secret: full asyncpg DATABASE_URL --------------------------------------
resource "aws_secretsmanager_secret" "database_url" {
  name_prefix = "${var.name}-database-url-"
  tags        = { Name = "${var.name}-database-url" }
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id = aws_secretsmanager_secret.database_url.id
  secret_string = format(
    "postgresql+asyncpg://%s:%s@%s:5432/%s",
    var.master_username,
    random_password.db.result,
    aws_rds_cluster.this.endpoint,
    var.database_name,
  )
}
