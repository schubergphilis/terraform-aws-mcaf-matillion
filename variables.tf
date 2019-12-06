// common variables

variable "availability_zone" {
  type        = string
  description = "Availability zone to deploy in"
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

variable "instance_type" {
  type        = string
  description = "AWS instance type"
  default     = "m5.large"
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
  description = "VPC subnet to deploy instance to"
}

// rds variables

variable "create_db_instance" {
  type        = bool
  description = "Set to true to create a postgresql RDS instance"
  default     = true
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
}