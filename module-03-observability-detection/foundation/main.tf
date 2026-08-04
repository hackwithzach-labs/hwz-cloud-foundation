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
  cloudtrail_multi_region        = true
  cloudtrail_log_file_validation = true
  cloudtrail_data_events         = true
  cloudtrail_use_kms             = true
}

# --------------------------------------------------------------------------
# NEW layer: the detection SOC. Weak (blind) or wired by detections_enabled.
# --------------------------------------------------------------------------
module "detection" {
  source = "./modules/detection"

  name_prefix           = local.name_prefix
  project               = var.project
  account_id            = data.aws_caller_identity.current.account_id
  region                = var.region
  app_log_group_name    = module.foundation.app_log_group
  cloudtrail_bucket_arn = "arn:aws:s3:::${module.foundation.cloudtrail_bucket}"

  detections_enabled = var.detections_enabled
  alert_email        = var.alert_email
}
