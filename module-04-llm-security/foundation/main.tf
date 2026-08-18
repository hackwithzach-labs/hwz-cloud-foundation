###############################################################################
# Module 4: LLM Security (Pillar 1) — root composition.
#
# Same pattern as every pillar from Chapter 8 on: the proven layers deploy
# PINNED HARDENED, and only THIS pillar's new layer -- the guardrail and the
# WAF -- starts weak, gated on guardrails_enabled / waf_enabled.
#
# The composition below used to be commented out with a note saying it "resolves
# on the course machine." It did not resolve anywhere, which meant this module
# quietly did NOT build on the hardened foundation the book says it builds on.
# It does now, flat and one level deep:
#
#   module "foundation"  -- Chapter 8, every control pinned strong
#   module "api"         -- Chapter 9, the private Bedrock path and scoped role
#   module "waf"         -- THIS chapter, weak by default
#
# COST: the foundation has no NAT gateways and no idle compute. The API layer's
# one hourly resource is the Bedrock interface endpoint. The WAF web ACL bills
# per ACL and per rule at a few dollars a month, prorated -- pennies for a lab
# session. Apply at session start, destroy at session end. scan/scan.py
# --selftest needs no AWS at all.
###############################################################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws   = { source = "hashicorp/aws", version = ">= 5.0" }
    local = { source = "hashicorp/local", version = ">= 2.4" }
  }
}

provider "aws" {
  region = var.region
}

locals {
  name_prefix = "${var.project}-${var.environment}"
}

# --------------------------------------------------------------------------
# PROVEN LAYER 1: the Chapter 8 foundation, pinned hardened.
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
# PROVEN LAYER 2: the Chapter 9 API. Private model path, one-model role.
# --------------------------------------------------------------------------
module "api" {
  source = "../../module-02-api-security/foundation/modules/api"

  name_prefix                = local.name_prefix
  project                    = var.project
  region                     = var.region
  vpc_id                     = module.foundation.vpc_id
  private_subnet_ids         = module.foundation.private_subnet_ids
  endpoint_security_group_id = module.foundation.endpoint_security_group_id
  secret_arn                 = module.foundation.secret_arn
}

# --------------------------------------------------------------------------
# THIS pillar's new layer #1: the AWS WAF on the API edge.
#
# log_group_arn is intentionally left unset. AWS requires a WAF logging
# destination whose name begins with `aws-waf-logs-`, so the foundation's
# /hwz-lab/app group cannot receive WAF logs no matter how you wire it. The
# chapter covers the dedicated-destination pattern; the lab does not pay for a
# second log group to prove a naming rule.
# --------------------------------------------------------------------------
module "waf" {
  source      = "./modules/waf"
  waf_enabled = var.waf_enabled
  name_prefix = local.name_prefix
  rate_limit  = var.rate_limit

  associate_resource_arn = var.api_resource_arn
}

# --------------------------------------------------------------------------
# THIS pillar's new layer #2: the guardrail. The guardrail runs in the API
# process (guard.py), so its "deployment" here is the posture flag the app and
# the scanner read. We emit a posture file so scan/scan.py reflects the real
# state of the deployed stack and the deploy -> scan -> harden -> scan loop is
# honest end to end.
# --------------------------------------------------------------------------
resource "local_file" "posture" {
  filename = "${path.module}/../scan/posture.json"
  content = jsonencode({
    input_guardrail           = var.guardrails_enabled
    output_guardrail          = var.guardrails_enabled
    instruction_data_boundary = var.guardrails_enabled
    waf_web_acl               = var.waf_enabled
    waf_rate_rule             = var.waf_enabled
  })
}

output "guardrails_enabled" {
  description = "Whether the LLM guardrail layer is on. False in baseline."
  value       = var.guardrails_enabled
}

output "waf_web_acl_arn" {
  description = "The WAF web ACL. Empty in baseline, because in baseline there is no WAF."
  value       = module.waf.web_acl_arn
}

output "api_role_arn" {
  description = "The composed Chapter 9 API role, proving this pillar builds on the proven layer rather than beside it."
  value       = module.api.api_role_arn
}

output "app_log_group" {
  description = "The foundation app log group the Chapter 10 detection layer watches."
  value       = module.foundation.app_log_group
}

