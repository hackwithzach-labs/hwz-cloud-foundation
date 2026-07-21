output "vpc_id"              { value = module.foundation.vpc_id }
output "private_subnet_ids"  { value = module.foundation.private_subnet_ids }
output "bedrock_endpoint_id" { value = aws_vpc_endpoint.bedrock_runtime.id }
output "api_role_arn"        { value = aws_iam_role.api.arn }
output "secret_arn"          { value = module.foundation.secret_arn }
output "app_log_group"       { value = module.foundation.app_log_group }
