###############################################################################
# module-03-observability-detection :: foundation/main.tf  (ROOT)
#
# Same "compose the foundation you already own" pattern as Module 2. It calls the
# Module 1 foundation PINNED HARDENED (you proved those controls in Chapter 8;
# re-weakening them teaches nothing) and adds only the new DETECTION layer on top.
#
# The one profile that flips here is detections_enabled, and it belongs to the
# NEW layer, not the foundation:
#   baseline.tfvars  -> detections_enabled = false  (the account is blind)
#   hardened.tfvars  -> detections_enabled = true   (the SOC is wired)
#
# Cost note: no NAT gateways, no idle compute. GuardDuty and Config bill pennies
# at lab scale and are torn down each session. Apply at session start, destroy at
# session end. hwz-detect --selftest needs no AWS at all.
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
    # Packages the Lambda producer's source into a deployment zip at plan time,
    # so the function ships from the repo with no build step and no S3 bucket.
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

locals {
  name_prefix = "${var.project}-${var.environment}"
}

# --------------------------------------------------------------------------
# Compose the Module 1 foundation, PINNED HARDENED. Same rule as every pillar:
# the foundation is fixed strong, only the new layer carries a weak baseline.
# --------------------------------------------------------------------------
module "foundation" {
  source = "../../module-01-cloud-foundation/foundation"

  project     = var.project
  environment = var.environment
  region      = var.region

  ssh_ingress_cidr               = "10.20.0.0/16"
  vpc_flow_logs                  = true
  s3_block_public_access         = true
  s3_default_encryption          = true
  s3_enforce_tls                 = true
  s3_versioning                  = true
  kms_strict_key_policy          = true
  kms_allow_cloudtrail           = true
  iam_deny_destructive           = true
  iam_scope_workload             = true
  cloudtrail_multi_region        = true
  cloudtrail_log_file_validation = true
  cloudtrail_data_events         = true
  cloudtrail_use_kms             = true
}

# --------------------------------------------------------------------------
# NEW layer A: the PRODUCERS. Who writes the log.
#
# This layer comes first, conceptually and in the dependency graph, because
# detection is arithmetic on a stream. No producer, no stream, and the most
# carefully configured filter in the account counts zero forever.
#
# It deploys all three shapes AWS offers -- Lambda (the service captures stdout
# into its own group), EC2 (nothing is automatic; agent plus IAM role or nothing
# ships), and Fargate (the task definition's log driver decides) -- and it has
# its own weak/hardened flip, log_delivery_enabled, separate from the detection
# flip. Two independent switches give students the state that actually bites
# real teams: detection perfectly configured, watching groups nothing writes to.
# --------------------------------------------------------------------------
module "producers" {
  source = "./modules/producers"

  name_prefix        = local.name_prefix
  project            = var.project
  region             = var.region
  app_log_group_name = module.foundation.app_log_group
  vpc_id             = module.foundation.vpc_id
  public_subnet_ids  = module.foundation.public_subnet_ids
  kms_key_arn        = module.foundation.kms_key_arn

  log_delivery_enabled = var.log_delivery_enabled
  log_retention_days   = var.log_retention_days
  lambda_producer      = var.lambda_producer
  container_producer   = var.container_producer
  ec2_producer         = var.ec2_producer
  instance_type        = var.instance_type
}

# --------------------------------------------------------------------------
# NEW layer B: the detection SOC. Weak (blind) or wired by detections_enabled.
#
# watched_log_groups is the wire between the two layers. The producers module
# reports every group it genuinely delivers into; the detection module attaches
# the app-layer filters to each one. Break that wire and you have rebuilt the
# classic production outage: dashboards green, filters present, nothing counted.
# --------------------------------------------------------------------------
module "detection" {
  source = "./modules/detection"

  name_prefix           = local.name_prefix
  project               = var.project
  account_id            = data.aws_caller_identity.current.account_id
  region                = var.region
  app_log_group_name    = module.foundation.app_log_group
  watched_log_groups    = module.producers.watched_log_groups
  cloudtrail_bucket_arn = "arn:aws:s3:::${module.foundation.cloudtrail_bucket}"

  detections_enabled = var.detections_enabled
  alert_email        = var.alert_email
}
