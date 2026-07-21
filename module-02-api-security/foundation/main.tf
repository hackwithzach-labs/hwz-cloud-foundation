###############################################################################
# module-02-api-security :: foundation/main.tf  (ROOT)
#
# This is the "compose the foundation you already own" idea in code. It does
# NOT redefine a VPC, a key, or an identity. It calls the module-1 foundation,
# pinned to its HARDENED values, and adds only the two things Pillar 2 needs on
# top: a Bedrock interface endpoint in the private subnets, and a workload role
# the API assumes.
#
# The foundation is pinned hardened because you already proved those controls
# in Chapter 8. Re-weakening proven ground teaches nothing. Only the NEW layer
# (the API app itself) has a weak baseline, and that baseline lives in the app,
# not here: app/config.py, HWZ_PROFILE=baseline vs hardened.
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

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

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
# NEW layer: Bedrock runtime endpoint in the foundation's PRIVATE subnets.
# The model is reachable from inside the VPC only. No public path.
# --------------------------------------------------------------------------
resource "aws_vpc_endpoint" "bedrock_runtime" {
  vpc_id              = module.foundation.vpc_id
  service_name        = "com.amazonaws.${var.region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = module.foundation.private_subnet_ids
  security_group_ids  = [module.foundation.endpoint_security_group_id]
  private_dns_enabled = true

  tags = {
    Project = var.project
    Name    = "${local.name_prefix}-bedrock-runtime"
  }
}

# --------------------------------------------------------------------------
# NEW layer: the API's workload role. Least privilege from the start: it may
# invoke ONE model family and read its ONE secret. Nothing else.
# --------------------------------------------------------------------------
data "aws_iam_policy_document" "api_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "api" {
  name               = "${local.name_prefix}-api-role"
  assume_role_policy = data.aws_iam_policy_document.api_assume.json
  tags               = { Project = var.project }
}

data "aws_iam_policy_document" "api_perms" {
  statement {
    sid       = "InvokeOneModelFamily"
    actions   = ["bedrock:InvokeModel"]
    resources = ["arn:aws:bedrock:${var.region}::foundation-model/${var.allowed_model}"]
  }
  statement {
    sid       = "ReadOwnSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [module.foundation.secret_arn]
  }
}

resource "aws_iam_role_policy" "api" {
  name   = "${local.name_prefix}-api-perms"
  role   = aws_iam_role.api.id
  policy = data.aws_iam_policy_document.api_perms.json
}
