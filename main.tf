locals {
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

resource "aws_iam_role_policy" "instance_role_policy" {
  name = "MatillionInstanceRolePolicy"
  role = aws_iam_role.instance_role.id

  policy = <<EOF
{
    "Statement": [
        {
            "Action": [
                "redshift:DescribeClusters"
            ],
            "Resource": [
                "*"
            ],
            "Effect": "Allow",
            "Sid": "StmtMinRedshift"
        },
        {
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:ListBucket",
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:GetBucketLocation"
            ],
            "Resource": [
                "*"
            ],
            "Effect": "Allow",
            "Sid": "StmtMinS3"
        },
        {
            "Action": [
                "sqs:DeleteMessage",
                "sqs:ListQueues",
                "sqs:ReceiveMessage",
                "sqs:SendMessage",
                "sqs:GetQueueUrl"
            ],
            "Resource": [
                "*"
            ],
            "Effect": "Allow",
            "Sid": "StmtMinSQS"
        },
        {
            "Action": [
                "rds:DescribeDBInstances"
            ],
            "Resource": [
                "*"
            ],
            "Effect": "Allow",
            "Sid": "StmtMinRDS"
        },
        {
            "Action": [
                "ec2:CreateSnapshot",
                "ec2:CreateTags",
                "ec2:DescribeInstances",
                "ec2:DescribeVolumes"
            ],
            "Resource": [
                "*"
            ],
            "Effect": "Allow",
            "Sid": "StmtMinEC2"
        },
        {
            "Action": [
                "sns:ListTopics",
                "sns:CreateTopic",
                "sns:Publish"
            ],
            "Resource": [
                "*"
            ],
            "Effect": "Allow",
            "Sid": "StmtMinSNS"
        },
        {
            "Action": [
                "cloudwatch:PutMetricData",
                "cloudwatch:ListMetrics"
            ],
            "Resource": [
                "*"
            ],
            "Effect": "Allow",
            "Sid": "StmtMinCloudwatch"
        },
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams"
            ],
            "Resource": [
                "arn:aws:logs:*:*:*"
            ],
            "Effect": "Allow",
            "Sid": "StmtMinCloudwatchLogs"
        },
        {
            "Action": [
                "kms:ListAliases",
                "kms:Encrypt",
                "kms:Decrypt"
            ],
            "Resource": [
                "*"
            ],
            "Effect": "Allow",
            "Sid": "StmtMinKMS"
        },
        {
            "Action": [
                "dynamodb:ListTables",
                "dynamodb:DescribeTable",
                "dynamodb:Scan"
            ],
            "Resource": "*",
            "Effect": "Allow",
            "Sid": "StmtMinDynamoDB"
        },
        {
            "Action": [
                "dms:CreateEndpoint",
                "dms:CreateReplicationTask",
                "dms:DeleteEndpoint",
                "dms:DeleteReplicationTask",
                "dms:DescribeConnections",
                "dms:DescribeEndpoints",
                "dms:DescribeReplicationInstances",
                "dms:DescribeReplicationTasks",
                "dms:ModifyEndpoint",
                "dms:StartReplicationTask",
                "dms:StopReplicationTask",
                "dms:TestConnection",
                "ec2:DescribeRegions",
                "iam:ListRoles",
                "iam:PassRole",
                "lambda:AddPermission",
                "lambda:CreateFunction",
                "lambda:DeleteFunction",
                "lambda:GetFunction",
                "lambda:GetPolicy",
                "lambda:RemovePermission",
                "lambda:UpdateFunctionCode",
                "lambda:UpdateFunctionConfiguration",
                "s3:GetBucketNotification",
                "s3:ListAllMyBuckets",
                "s3:PutBucketNotification",
                "sqs:ChangeMessageVisibility",
                "sqs:DeleteMessage",
                "sqs:ListQueues",
                "sqs:ReceiveMessage"
            ],
            "Resource": "*",
            "Effect": "Allow",
            "Sid": "CDCPermissions"
        }
    ]
}
EOF
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
  cidr_blocks       = ["10.0.0.0/16"]
  from_port         = 80
  ipv6_cidr_blocks  = []
  prefix_list_ids   = []
  protocol          = "tcp"
  security_group_id = aws_security_group.instance.id
  self              = false
  to_port           = 80
  type              = "ingress"
}

resource "aws_security_group_rule" "instance_http_in_alb" {
  from_port                = 80
  ipv6_cidr_blocks         = []
  prefix_list_ids          = []
  protocol                 = "tcp"
  security_group_id        = aws_security_group.instance.id
  source_security_group_id = aws_security_group.alb.id
  to_port                  = 80
  type                     = "ingress"
}

resource "aws_security_group_rule" "instance_5071_in_self" {
  from_port         = 5701
  ipv6_cidr_blocks  = []
  prefix_list_ids   = []
  protocol          = "tcp"
  security_group_id = aws_security_group.instance.id
  self              = true
  to_port           = 5701
  type              = "ingress"
}

resource "aws_security_group_rule" "instance_all_out" {
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 0
  ipv6_cidr_blocks  = []
  prefix_list_ids   = []
  protocol          = "-1"
  security_group_id = aws_security_group.instance.id
  self              = false
  to_port           = 0
  type              = "egress"
}

resource "aws_instance" "default" {
  count                                = var.instance_count
  ami                                  = data.aws_ami.snowflake.id
  instance_type                        = var.instance_type
  iam_instance_profile                 = aws_iam_instance_profile.default.name
  instance_initiated_shutdown_behavior = var.shutdown_behavior
  subnet_id                            = element(var.subnet_ids, count.index)
  availability_zone                    = var.availability_zone
  key_name                             = var.key_name
  monitoring                           = var.monitoring
  tags                                 = merge(local.tags, var.tags)

  vpc_security_group_ids = [aws_security_group.instance.id]

  root_block_device {
    volume_type           = var.root_volume_type
    volume_size           = var.root_volume_size
    delete_on_termination = var.root_volume_delete_on_termination
  }

  lifecycle {
    ignore_changes = [key_name, ami, user_data]
  }
}

// deploy RDS postgres instance

resource "aws_security_group" "rds" {
  name_prefix = "MatillionPostgresSecurityGroup-"
  description = "MatillionPostgresSecurityGroup"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, var.tags)
}

resource "aws_security_group_rule" "rds_postgres_in_cidr" {
  cidr_blocks       = ["10.0.1.0/24"]
  description       = "PostgreSQL"
  from_port         = 5432
  ipv6_cidr_blocks  = []
  prefix_list_ids   = []
  protocol          = "tcp"
  security_group_id = aws_security_group.rds.id
  self              = false
  to_port           = 5432
  type              = "ingress"
}

resource "aws_security_group_rule" "rds_all_out" {
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "All protocols"
  from_port         = 0
  ipv6_cidr_blocks  = []
  prefix_list_ids   = []
  protocol          = "-1"
  security_group_id = aws_security_group.rds.id
  self              = false
  to_port           = 0
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
  multi_az                        = var.db_multi_az
  identifier                      = "Matillion-RDS"
  availability_zone               = var.availability_zone
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
  count            = var.instance_count
  target_group_arn = aws_lb_target_group.http.arn
  target_id        = element(aws_instance.default.*.id, count.index)
}

resource "aws_security_group" "alb" {
  name_prefix = "MatillionALBSecurityGroup-"
  description = "MatillionALBSecurityGroup"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, var.tags)
}

resource "aws_security_group_rule" "alb_http_in" {
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 80
  ipv6_cidr_blocks  = []
  prefix_list_ids   = []
  protocol          = "tcp"
  security_group_id = aws_security_group.alb.id
  self              = false
  to_port           = 80
  type              = "ingress"
}

resource "aws_security_group_rule" "alb_https_in" {
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 443
  ipv6_cidr_blocks  = []
  prefix_list_ids   = []
  protocol          = "tcp"
  security_group_id = aws_security_group.alb.id
  self              = false
  to_port           = 443
  type              = "ingress"
}

resource "aws_security_group_rule" "alb_all_out" {
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 0
  ipv6_cidr_blocks  = []
  prefix_list_ids   = []
  protocol          = "-1"
  security_group_id = aws_security_group.alb.id
  self              = false
  to_port           = 0
  type              = "egress"
}

resource "aws_lb" "default" {
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.subnet_ids
  tags               = merge(local.tags, var.tags)
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.default.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    target_group_arn = aws_lb_target_group.http.arn
    type             = "forward"
  }
}
