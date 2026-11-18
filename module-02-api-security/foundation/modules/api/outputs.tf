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

output "model_invoke_id" {
  description = "The id the app passes to bedrock-runtime as modelId (HWZ_MODEL_ID): the inference profile, not the bare model."
  value       = local.inference_profile_id
}
