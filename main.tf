locals {
  create_alb_http_listener  = var.create_alb && var.alb_certificate_arn == null ? true : false
  create_alb_https_listener = var.create_alb && var.alb_certificate_arn != null ? true : false

  tags = {
    MatillionType = "snowflake"
    Name          = "Matillion-ETL"
  }
}

// deploy instance

data "aws_ami" "snowflake" {
  most_recent = true
  owners      = ["679593333241"]

  filter {
    name   = "name"
    values = ["matillion-etl-for-snowflake-ami-*"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_kms_key" "default" {
  key_id = var.kms_key_id
}

resource "aws_iam_role" "instance_role" {
  name = "MatillionRole"

  assume_role_policy = <<EOF
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "ssm_managed_instance_core" {
  count      = var.enable_ssm_managed_instance ? 1 : 0
  role       = aws_iam_role.instance_role.id
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "instance_role_policy" {
  name   = "MatillionInstanceRolePolicy"
  role   = aws_iam_role.instance_role.id
  policy = var.instance_role_policy
}

resource "aws_iam_instance_profile" "default" {
  name = "MatillionInstanceProfile"
  role = aws_iam_role.instance_role.id
}

resource "aws_security_group" "instance" {
  name_prefix = "MatillionInstanceSecurityGroup-"
  description = "MatillionInstanceSecurityGroup"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, var.tags)
}

resource "aws_security_group_rule" "instance_http_in_cidrs" {
  count             = length(var.instance_http_in_cidrs) > 0 ? 1 : 0
  cidr_blocks       = var.instance_http_in_cidrs
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  security_group_id = aws_security_group.instance.id
  type              = "ingress"
}

resource "aws_security_group_rule" "instance_https_in_cidrs" {
  count             = length(var.instance_https_in_cidrs) > 0 ? 1 : 0
  cidr_blocks       = var.instance_https_in_cidrs
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.instance.id
  type              = "ingress"
}

resource "aws_security_group_rule" "instance_http_in_alb" {
  count                    = var.create_alb ? 1 : 0
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  security_group_id        = aws_security_group.instance.id
  source_security_group_id = aws_security_group.alb.0.id
  type                     = "ingress"
}

resource "aws_security_group_rule" "instance_5071_in_self" {
  count             = var.instance_count > 1 ? 1 : 0
  from_port         = 5701
  to_port           = 5701
  protocol          = "tcp"
  security_group_id = aws_security_group.instance.id
  type              = "ingress"
}

resource "aws_security_group_rule" "instance_all_out" {
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = aws_security_group.instance.id
  type              = "egress"
}

resource "aws_instance" "default" {
  count                                = var.instance_count
  ami                                  = data.aws_ami.snowflake.id
  instance_type                        = var.instance_type
  iam_instance_profile                 = aws_iam_instance_profile.default.name
  instance_initiated_shutdown_behavior = var.shutdown_behavior
  subnet_id                            = element(var.subnet_ids, count.index)
  availability_zone                    = element(var.availability_zones, count.index)
  associate_public_ip_address          = var.associate_public_ip_address
  key_name                             = var.key_name
  monitoring                           = var.monitoring
  tags                                 = merge(local.tags, var.tags)

  vpc_security_group_ids = [aws_security_group.instance.id]

  root_block_device {
    volume_type           = var.root_volume_type
    volume_size           = var.root_volume_size
    delete_on_termination = var.root_volume_delete_on_termination
    encrypted             = true
    kms_key_id            = data.aws_kms_key.default.arn
  }

  lifecycle {
    ignore_changes = [key_name, ami, user_data]
  }
}

// deploy RDS postgres instance

resource "aws_security_group" "rds" {
  count       = var.create_db_instance ? 1 : 0
  name_prefix = "MatillionPostgresSecurityGroup-"
  description = "MatillionPostgresSecurityGroup"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, var.tags)
}

resource "aws_security_group_rule" "rds_postgres_in_cidr" {
  count                    = var.create_db_instance ? 1 : 0
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.instance.id
  security_group_id        = aws_security_group.rds.0.id
  type                     = "ingress"
}

resource "aws_security_group_rule" "rds_all_out" {
  count             = var.create_db_instance ? 1 : 0
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = aws_security_group.rds.0.id
  type              = "egress"
}

module "db" {
  // We need to revert to the published module below once the PR for this branch has been merged
  source = "git::github.com/shoekstra/terraform-aws-rds.git?ref=make_lowercase_when_needed"

  // source  = "terraform-aws-modules/rds/aws"
  // version = "~> 2.5.0"

  // RDS
  create_db_instance              = var.create_db_instance
  create_db_subnet_group          = var.create_db_subnet_group
  create_db_parameter_group       = var.create_db_instance
  multi_az                        = var.db_multi_az
  identifier                      = "Matillion-RDS"
  availability_zone               = var.availability_zones[0]
  engine                          = "postgres"
  engine_version                  = var.db_engine_version
  instance_class                  = var.db_instance_class
  subnet_ids                      = var.db_subnet_ids
  allocated_storage               = var.db_allocated_storage
  storage_encrypted               = true
  deletion_protection             = true
  skip_final_snapshot             = false
  final_snapshot_identifier       = "Matillion"
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  auto_minor_version_upgrade      = true
  apply_immediately               = var.db_apply_immediately
  copy_tags_to_snapshot           = true
  vpc_security_group_ids          = ["sg-029c95a5117ff3543"]
  tags                            = merge(local.tags, var.tags)

  // RDS backup & maintenance
  backup_window           = var.db_backup_window
  backup_retention_period = var.db_backup_retention_period
  maintenance_window      = var.db_maintenance_window

  // DB parameter group
  family               = "postgres${var.db_major_engine_version}"
  parameter_group_name = "matillion-rds"
  parameters = [
    {
      name  = "timezone"
      value = "Europe/Amsterdam"
    }
  ]

  // DB option group
  major_engine_version = var.db_major_engine_version

  // DB
  name     = "matillion"
  username = var.db_username
  password = var.db_password
  port     = "5432"
}

// deploy ALB

resource "aws_lb_target_group" "http" {
  count       = var.create_alb ? 1 : 0
  name        = "Matillion-HTTP"
  port        = "80"
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "instance"
  tags        = merge(local.tags, var.tags)

  health_check {
    path                = "/"
    interval            = 10
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
    matcher             = "200,302"
  }

  stickiness {
    type            = "lb_cookie"
    cookie_duration = "86400"
    enabled         = true
  }
}

resource "aws_lb_target_group_attachment" "instance" {
  count            = var.create_alb ? var.instance_count : 0
  target_group_arn = aws_lb_target_group.http.0.arn
  target_id        = element(aws_instance.default.*.id, count.index)
}

resource "aws_security_group" "alb" {
  count       = var.create_alb ? 1 : 0
  name_prefix = "MatillionALBSecurityGroup-"
  description = "MatillionALBSecurityGroup"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, var.tags)
}

resource "aws_security_group_rule" "alb_http_in" {
  count             = var.create_alb ? 1 : 0
  cidr_blocks       = var.alb_http_in_cidrs
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  security_group_id = aws_security_group.alb.0.id
  type              = "ingress"
}

resource "aws_security_group_rule" "alb_https_in" {
  count             = local.create_alb_https_listener ? 1 : 0
  cidr_blocks       = var.alb_http_in_cidrs
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.alb.0.id
  type              = "ingress"
}

resource "aws_security_group_rule" "alb_all_out" {
  count             = var.create_alb ? 1 : 0
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = aws_security_group.alb.0.id
  type              = "egress"
}

resource "aws_lb" "default" {
  count              = var.create_alb ? 1 : 0
  name               = "Matillion"
  internal           = var.create_global_accelerator ? true : false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.0.id]
  subnets            = var.subnet_ids
  tags               = merge(local.tags, var.tags)
}

resource "aws_lb_listener" "http" {
  count             = var.create_alb ? 1 : 0
  load_balancer_arn = aws_lb.default.0.arn
  port              = 80
  protocol          = "HTTP"

  dynamic "default_action" {
    for_each = var.create_alb ? [1] : []

    content {
      type             = local.create_alb_http_listener ? "forward" : "redirect"
      target_group_arn = local.create_alb_http_listener ? aws_lb_target_group.http.0.arn : null

      redirect {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }
}

resource "aws_lb_listener" "https" {
  count             = local.create_alb_https_listener ? 1 : 0
  load_balancer_arn = aws_lb.default.0.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = var.alb_ssl_policy
  certificate_arn   = var.alb_certificate_arn

  default_action {
    target_group_arn = aws_lb_target_group.http.0.arn
    type             = "forward"
  }
}

resource "aws_globalaccelerator_accelerator" "default" {
  count           = var.create_global_accelerator && var.create_alb ? 1 : 0
  name            = "Matillion"
  ip_address_type = "IPV4"
  enabled         = true
}

resource "aws_globalaccelerator_listener" "default" {
  count           = var.create_global_accelerator && var.create_alb ? 1 : 0
  accelerator_arn = aws_globalaccelerator_accelerator.default.0.id
  protocol        = "TCP"

  port_range {
    from_port = 80
    to_port   = 80
  }

  port_range {
    from_port = 443
    to_port   = 443
  }
}

resource "aws_globalaccelerator_endpoint_group" "default" {
  count             = var.create_global_accelerator && var.create_alb ? 1 : 0
  health_check_port = 80
  listener_arn      = aws_globalaccelerator_listener.default.0.id

  endpoint_configuration {
    endpoint_id = aws_lb.default.0.arn
    weight      = 100
  }

  lifecycle {
    ignore_changes = [
      health_check_path
    ]
  }
}

