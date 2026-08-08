output "vpc_id" { value = module.foundation.vpc_id }
output "private_subnet_ids" { value = module.foundation.private_subnet_ids }
output "bedrock_endpoint_id" { value = module.api.bedrock_endpoint_id }
output "api_role_arn" { value = module.api.api_role_arn }
output "secret_arn" { value = module.foundation.secret_arn }
output "app_log_group" { value = module.foundation.app_log_group }
