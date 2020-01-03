// common variables

variable "availability_zones" {
  type        = list(string)
  description = "Availability zones to deploy in"
}

variable "instance_count" {
  type        = number
  description = "Number of Matillion instances to deploy"
  default     = 1
}

variable "vpc_id" {
  type        = string
  description = "VPC ID"
}

variable "tags" {
  type        = map(string)
  description = "A mapping of tags to assign to the bucket"
  default     = {}
}

// instance variables

variable "associate_public_ip_address" {
  type        = bool
  description = "Set to false to disable the use of a public IP address"
  default     = true
}

variable "instance_type" {
  type        = string
  description = "AWS instance type"
  default     = "t2.medium"
}

variable "instance_http_in_cidrs" {
  type        = list(string)
  description = "A list of CIDRs allowing HTTP access to the Matillion instance(s)"
  default     = []
}

variable "instance_https_in_cidrs" {
  type        = list(string)
  description = "A list of CIDRs allowing HTTPS access to the Matillion instance(s)"
  default     = []
}

variable "instance_role_policy" {
  type        = string
  description = "Instance role policy for Matillion"
  default     = <<POLICY
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
POLICY
}

variable "key_name" {
  type        = string
  description = "Name of the key pair to use"
}

variable "monitoring" {
  type        = bool
  description = "Enable detailed monitoring"
  default     = true
}

variable "root_volume_delete_on_termination" {
  type        = bool
  description = "Whether to delete root block device on instance termination"
  default     = true
}

variable "root_volume_size" {
  type        = number
  description = "Root block device volume size"
  default     = 40
}

variable "root_volume_type" {
  type        = string
  description = "Root block device volume type"
  default     = "gp2"
}

variable "shutdown_behavior" {
  type        = string
  description = "Instance initiated shutdown behaviour"
  default     = "stop"
}

variable "vpc_security_group_ids" {
  type        = list(string)
  description = "VPC security group IDs to associate instance with"
  default     = []
}

variable "subnet_ids" {
  type        = list(string)
  description = "VPC subnet IDs to deploy instance(s) to"
}

// rds variables

variable "create_db_instance" {
  type        = bool
  description = "Set to true to create a postgresql RDS instance"
  default     = false
}

variable "create_db_subnet_group" {
  type        = bool
  description = "Set to true to create a RDS subnet group"
  default     = false
}

variable "db_apply_immediately" {
  type        = bool
  description = "Apply RDS changes immediately"
  default     = true
}

variable "db_allocated_storage" {
  type        = number
  description = "Database allocated storage"
  default     = 20
}

variable "db_backup_retention_period" {
  type        = number
  description = "Number of days to keep database backups"
  default     = 30
}

variable "db_backup_window" {
  type        = string
  description = "Database backup window"
  default     = "05:19-05:49"
}

variable "db_maintenance_window" {
  type        = string
  description = "Database maintenance window"
  default     = "Mon:00:00-Mon:03:00"
}

variable "db_instance_class" {
  type        = string
  description = "RDS instance class"
  default     = "db.t2.medium"
}

variable "db_engine_version" {
  type        = string
  description = "Database engine version"
  default     = "9.6.15"
}

variable "db_major_engine_version" {
  type        = string
  description = "Database major engine version"
  default     = "9.6"
}

variable "db_multi_az" {
  type        = bool
  description = "Set to true to deploy in multiple AZes"
  default     = true
}

variable "db_username" {
  type        = string
  description = "Database username"
  default     = "matillion"
}

variable "db_password" {
  type        = string
  description = "Database password"
  default     = "YourPwdShouldBeLongAndSecure!"
}

variable "db_subnet_ids" {
  type        = list(string)
  description = "Database subnet IDs"
  default     = []
}

// alb variables

variable "create_alb" {
  type        = bool
  description = "Set to true to create an Application Load Balancer"
  default     = false
}

variable "alb_certificate_arn" {
  type        = string
  description = "Certificate ARN to apply to HTTPS listener"
  default     = null
}

variable "alb_http_in_cidrs" {
  type        = list(string)
  description = "CIDRs allowed to access the ALB via HTTP and HTTPS"
  default     = []
}

variable "alb_ssl_policy" {
  type        = string
  description = "ALB SSL Policy"
  default     = "ELBSecurityPolicy-TLS-1-2-Ext-2018-06"
}

// global accelerator variables

variable "create_global_accelerator" {
  type        = bool
  description = "Set to true to create a Global Accelerator"
  default     = false
}
