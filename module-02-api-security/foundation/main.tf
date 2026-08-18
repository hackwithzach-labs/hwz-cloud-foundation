###############################################################################
# module-02-api-security :: foundation/main.tf  (ROOT)
#
# This is the "compose the foundation you already own" idea in code. It does
# NOT redefine a VPC, a key, or an identity. It calls the module-1 foundation,
# pinned to its HARDENED values, and adds only the layer Pillar 2 needs on top:
# a Bedrock interface endpoint in the private subnets, and a workload role the
# API assumes.
#
# The foundation is pinned hardened because you already proved those controls
# in Chapter 8. Re-weakening proven ground teaches nothing. Only the NEW layer
# (the API app itself) has a weak baseline, and that baseline lives in the app,
# not here: app/config.py, HWZ_PROFILE=baseline vs hardened.
#
# WHAT CHANGED: the three API resources moved out of this file into
# ./modules/api. Behaviour is identical -- same endpoint, same role, same
# policy -- but the layer is now a CHILD module, which means Chapters 11, 12,
# 13 and the capstone can compose it directly instead of calling this root.
# Roots calling roots inherit provider configuration in ways that break
# destroy, and the capstone would have been four levels deep.
#
# Cost note: the ONE billable hourly resource here is the interface endpoint.
# There are no NAT gateways by design. Apply at the start of a session, destroy
# at the end. Bedrock itself is on-demand per-token with no idle cost.
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

locals {
  name_prefix = "${var.project}-${var.environment}"
}

# --------------------------------------------------------------------------
# Compose the module-1 foundation, PINNED HARDENED.
# Every foundation flag is fixed to its strong value here. This root does not
# expose those flags, so a pillar deploy can never accidentally deploy a weak
# foundation. That is the locked rule: foundation hardened, new layer weak.
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
# NEW layer: the Chapter 9 API infrastructure, now a reusable child module.
# --------------------------------------------------------------------------
module "api" {
  source = "./modules/api"

  name_prefix                = local.name_prefix
  project                    = var.project
  region                     = var.region
  vpc_id                     = module.foundation.vpc_id
  private_subnet_ids         = module.foundation.private_subnet_ids
  endpoint_security_group_id = module.foundation.endpoint_security_group_id
  secret_arn                 = module.foundation.secret_arn
  allowed_model              = var.allowed_model
}
