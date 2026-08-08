###############################################################################
# modules/api :: outputs.tf
###############################################################################

output "bedrock_endpoint_id" {
  description = "The Bedrock runtime interface endpoint. Proof the model path is private."
  value       = aws_vpc_endpoint.bedrock_runtime.id
}

output "api_role_arn" {
  description = "ARN of the API workload role. Later pillars attach their tool policies relative to this identity."
  value       = aws_iam_role.api.arn
}

output "api_role_name" {
  description = "Name of the API workload role, for policy attachments in later pillars."
  value       = aws_iam_role.api.name
}
