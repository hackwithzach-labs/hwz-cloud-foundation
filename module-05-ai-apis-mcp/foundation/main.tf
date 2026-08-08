###############################################################################
# Module 5: AI APIs and MCP (Pillar 2) — root composition.
#
# The Ch8 foundation and the Ch9 API deploy PINNED HARDENED; only THIS pillar's
# new layer -- the MCP server and its tools -- starts weak, gated on the five
# flags. One apply at session start, one destroy at the end.
#
# The composition below used to be a comment claiming it resolved "on the course
# machine." It resolved nowhere, so this module did not actually build on the
# layers the book says it builds on. It does now, flat:
#
#   module "foundation"  -- Chapter 8, pinned strong
#   module "api"         -- Chapter 9, pinned strong
#   module "tools"       -- THIS chapter, weak by default
#
# COST: no NAT gateways, no idle compute. The one hourly resource in the whole
# stack is the Bedrock interface endpoint from the API layer. IAM roles are
# free. scan/scan.py --selftest needs no AWS at all.
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
# PROVEN LAYER 2: the Chapter 9 API.
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
# THIS pillar's new layer: per-tool least-privilege roles.
#
# The whole Pillar 2 lesson lives in one flag. Off, every tool the model can
# call runs under one broad identity, so a single hijacked tool call reaches
# everything. On, each tool assumes its OWN scoped role and a hijack is
# contained to that tool's job.
# --------------------------------------------------------------------------
module "tools" {
  source          = "./modules/tools"
  tool_least_priv = var.tool_least_priv
  name_prefix     = local.name_prefix
}

# The MCP server, the tool allowlist, the egress locking, and the tool-call
# guardrail are app + network concerns. Their deployed state is recorded here
# so scan/scan.py reflects reality and the deploy -> scan -> harden -> scan loop
# is honest end to end.
resource "local_file" "posture" {
  filename = "${path.module}/../scan/posture.json"
  content = jsonencode({
    mcp_authenticated  = var.mcp_authenticated
    tool_least_priv    = var.tool_least_priv
    toolcall_guardrail = var.toolcall_guardrail
    tool_allowlist     = var.tool_allowlist
    egress_locked      = var.egress_locked
  })
}

output "tool_least_priv" {
  description = "Whether each tool gets its own scoped role. False in baseline."
  value       = module.tools.least_priv_enabled
}

output "api_role_arn" {
  description = "The composed Chapter 9 API role."
  value       = module.api.api_role_arn
}

output "app_log_group" {
  description = "The foundation app log group the Chapter 10 detection layer watches."
  value       = module.foundation.app_log_group
}
