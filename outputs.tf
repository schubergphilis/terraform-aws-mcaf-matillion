output "role_arn" {
  value       = aws_iam_role.instance_role.arn
  description = "ARN of the Matillion role"
}
