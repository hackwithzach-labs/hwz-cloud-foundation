output "app_log_group_name" { value = aws_cloudwatch_log_group.app.name }
output "app_log_group_arn" { value = aws_cloudwatch_log_group.app.arn }
output "flow_log_group_arn" { value = aws_cloudwatch_log_group.flow.arn }
output "flow_log_role_arn" { value = aws_iam_role.flow.arn }
