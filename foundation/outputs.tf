###############################################################################
# outputs.tf  (ROOT)
# These are the handles each pillar consumes. If a pillar needs the private
# subnets for a Bedrock endpoint, it reads module.vpc.private_subnet_ids.
###############################################################################

output "vpc_id" {
  description = "The foundation VPC id."
  value       = module.vpc.vpc_id
}

output "vpc_cidr" {
  description = "The foundation VPC CIDR."
  value       = module.vpc.vpc_cidr
}

output "public_subnet_ids" {
  description = "Public subnet ids (for load balancers, bastions)."
  value       = module.vpc.public_subnet_ids
}

output "private_subnet_ids" {
  description = "Private subnet ids. Pillar 2 attaches the Bedrock VPC endpoint here."
  value       = module.vpc.private_subnet_ids
}

output "endpoint_security_group_id" {
  description = "Security group for interface VPC endpoints (443 from the VPC)."
  value       = module.vpc.endpoint_security_group_id
}

output "kms_key_arn" {
  description = "The shared customer-managed KMS key ARN."
  value       = module.kms.key_arn
}

output "workload_role_arn" {
  description = "The role your pillar apps assume."
  value       = module.iam.role_arn
}

output "data_bucket" {
  description = "The general-purpose data bucket name."
  value       = module.s3.bucket_id
}

output "secret_arn" {
  description = "The Secrets Manager secret ARN pillars read credentials from."
  value       = module.secrets.secret_arn
}

output "cloudtrail_arn" {
  description = "The account CloudTrail ARN."
  value       = module.cloudtrail.trail_arn
}

output "cloudtrail_bucket" {
  description = "The bucket CloudTrail writes logs to."
  value       = module.cloudtrail.trail_bucket_id
}

output "app_log_group" {
  description = "CloudWatch log group your apps and VPC flow logs write to."
  value       = module.observability.app_log_group_name
}
