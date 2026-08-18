###############################################################################
# Module 6: Agentic AI Security (Pillar 3) — root composition.
#
# The deepest composition in the course before the capstone. Three proven
# layers, pinned hardened, and one new layer that starts weak:
#
#   module "foundation"  -- Chapter 8, pinned strong
#   module "api"         -- Chapter 9, pinned strong
#   module "tools"       -- Chapter 12, pinned strong (least privilege ON)
#   module "agent"       -- THIS chapter, weak by default
#
# Read that list twice, because it is the argument of the whole book. By the
# time an agent exists, three layers of control already exist underneath it,
# every one of them proven by a scan you ran yourself. The agent is not
# defended by a single clever control; it is defended by everything you built
# before it. The capstone in Chapter 15 adds exactly one more line to this list.
#
# Note module "tools" is pinned tool_least_priv = true. Chapter 12 proved that
# control, so Chapter 13 does not get to re-weaken it. The only weakness in
# this apply belongs to the agent loop itself.
#
# COST: no NAT gateways, no idle compute. The one hourly resource in the whole
# stack is the Bedrock interface endpoint from the API layer; everything else
# here is IAM, which is free. Apply at session start, destroy at session end.
# scan/scan.py --selftest needs no AWS at all.
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
# PROVEN LAYER 1: the Chapter 8 foundation.
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
# PROVEN LAYER 3: the Chapter 12 per-tool roles, PINNED LEAST PRIVILEGE.
# You proved this control in Pillar 2. It does not get re-weakened here.
# --------------------------------------------------------------------------
module "tools" {
  source          = "../../module-05-ai-apis-mcp/foundation/modules/tools"
  tool_least_priv = true
  name_prefix     = "${local.name_prefix}-mcp"
}

# --------------------------------------------------------------------------
# THIS pillar's new layer: the agent's own tool roles.
#
# When tool_least_priv is on, each tool the AGENT can call assumes its own
# scoped role, so a hijacked step cannot cascade beyond that one tool's job.
# When off, the whole loop runs under one broad role and excessive agency
# compounds across every pass of the loop.
# --------------------------------------------------------------------------
module "agent" {
  source          = "./modules/agent"
  tool_least_priv = var.tool_least_priv
  name_prefix     = local.name_prefix
}

# The remaining five loop controls are runtime + orchestrator concerns. Their
# deployed state is recorded here so scan/scan.py reflects reality and the
# deploy -> scan -> attack -> harden -> scan loop is honest end to end.
resource "local_file" "posture" {
  filename = "${path.module}/../scan/posture.json"
  content = jsonencode({
    goal_locked      = var.goal_locked
    memory_guardrail = var.memory_guardrail
    tool_least_priv  = var.tool_least_priv
    step_budget      = var.step_budget
    hitl_approval    = var.hitl_approval
    run_audit        = var.run_audit
  })
}

output "tool_least_priv" {
  description = "Whether each agent tool gets its own scoped role. False in baseline."
  value       = module.agent.least_priv_enabled
}

output "api_role_arn" {
  description = "The composed Chapter 9 API role."
  value       = module.api.api_role_arn
}

output "app_log_group" {
  description = "The foundation app log group the Chapter 10 detection layer watches."
  value       = module.foundation.app_log_group
}
