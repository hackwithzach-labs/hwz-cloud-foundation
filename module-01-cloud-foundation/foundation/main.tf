###############################################################################
# main.tf  (ROOT)
#
# This is the "start with the end in mind" picture in code. It wires the seven
# foundation modules together in dependency order:
#
#   vpc  ->  networking every pillar can attach to (public + PRIVATE subnets)
#   kms  ->  one customer-managed key the whole foundation shares
#   iam  ->  a workload role your apps assume (over-scoped in baseline)
#   s3   ->  a data bucket (unencrypted + public-capable in baseline)
#   secrets     ->  a Secrets Manager secret (no broken rotation Lambda here)
#   cloudtrail  ->  an account trail with its OWN correctly-policied log bucket
#   observability -> a CloudWatch log group flow logs and apps write to
#
# Each pillar later brings its own root that calls only the modules it needs.
# This foundation root calls all seven so you can see the whole board.
###############################################################################

locals {
  name_prefix = "${var.project}-${var.environment}"
  account_id  = data.aws_caller_identity.current.account_id
  region      = data.aws_region.current.name
}

module "vpc" {
  source = "./modules/vpc"

  name_prefix           = local.name_prefix
  vpc_cidr              = var.vpc_cidr
  azs                   = var.azs
  public_subnet_cidrs   = var.public_subnet_cidrs
  private_subnet_cidrs  = var.private_subnet_cidrs
  endpoint_ingress_cidr = var.ssh_ingress_cidr
  enable_flow_logs      = var.vpc_flow_logs
  flow_logs_group_arn   = module.observability.flow_log_group_arn
  flow_logs_role_arn    = module.observability.flow_log_role_arn
}

module "kms" {
  source = "./modules/kms"

  name_prefix       = local.name_prefix
  account_id        = local.account_id
  region            = local.region
  strict_key_policy = var.kms_strict_key_policy
  allow_cloudtrail  = var.kms_allow_cloudtrail
  workload_role_arn = module.iam.role_arn
}

module "iam" {
  source = "./modules/iam"

  name_prefix      = local.name_prefix
  deny_destructive = var.iam_deny_destructive
}

module "s3" {
  source = "./modules/s3"

  name_prefix         = local.name_prefix
  block_public_access = var.s3_block_public_access
  default_encryption  = var.s3_default_encryption
  kms_key_arn         = module.kms.key_arn
  enforce_tls         = var.s3_enforce_tls
  versioning          = var.s3_versioning
}

module "secrets" {
  source = "./modules/secrets"

  name_prefix = local.name_prefix
  kms_key_arn = module.kms.key_arn
}

module "cloudtrail" {
  source = "./modules/cloudtrail"

  name_prefix         = local.name_prefix
  account_id          = local.account_id
  region              = local.region
  multi_region        = var.cloudtrail_multi_region
  log_file_validation = var.cloudtrail_log_file_validation
  data_events         = var.cloudtrail_data_events
  use_kms             = var.cloudtrail_use_kms
  kms_key_arn         = module.kms.key_arn
}

module "observability" {
  source = "./modules/observability"

  name_prefix    = local.name_prefix
  retention_days = var.log_retention_days
}
