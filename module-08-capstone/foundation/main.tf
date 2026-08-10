###############################################################################
# module-08-capstone :: foundation/main.tf
#
# THE ONLY ROOT IN THE COURSE THAT STANDS EVERYTHING AT ONCE.
#
# Read the module blocks below as the argument of the whole book: the
# foundation is composed and PINNED HARDENED -- there is no weak option for it
# here and there never was after Chapter 8 -- and only the new layers carry a
# weak profile. That is the locked rule, and this file is where it either holds
# or is exposed as a slogan.
#
# The capstone is the highest hourly cost in the course because every hourly
# resource you have met is standing simultaneously. Plan it as one sitting.
# Chapter 15 ends with the full teardown sweep; run it the same day.
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws   = { source = "hashicorp/aws", version = ">= 5.0" }
    local = { source = "hashicorp/local", version = ">= 2.4" }
  }
}

provider "aws" {
  region = var.region
}

# ---------------------------------------------------------------------------
# Chapter 8 — the cloud foundation, every control pinned strong.
# ---------------------------------------------------------------------------
module "foundation" {
  source = "../../module-01-cloud-foundation/foundation"

  project     = var.project
  environment = var.environment
  region      = var.region

  # Pinned. A capstone that could stand up a weak foundation by accident would
  # teach the opposite of the lesson.
  s3_encryption            = true
  s3_block_public_access   = true
  s3_tls_only              = true
  s3_versioning            = true
  sg_restrict_ingress      = true
  vpc_flow_logs            = true
  iam_scope_workload       = true
  iam_destructive_deny     = true
  kms_key_rotation         = true
  kms_strict_key_policy    = true
  cloudtrail_multi_region  = true
  cloudtrail_validation    = true
  cloudtrail_data_events   = true
  cloudtrail_kms_encrypted = true
}

# ---------------------------------------------------------------------------
# Chapter 9 — the private Bedrock path and the scoped API role.
# ---------------------------------------------------------------------------
module "api" {
  source = "../../module-02-api-security/foundation/modules/api"

  project            = var.project
  environment        = var.environment
  region             = var.region
  vpc_id             = module.foundation.vpc_id
  private_subnet_ids = module.foundation.private_subnet_ids
  kms_key_arn        = module.foundation.kms_key_arn
}

# ---------------------------------------------------------------------------
# The posture file. attack/end_to_end.py and visual/app.py read THIS, not the
# tfvars, so the attack can never claim a control you did not deploy.
# ---------------------------------------------------------------------------
resource "local_file" "posture" {
  filename = "${path.module}/posture.json"

  content = jsonencode({
    # Quoted keys: the attack reads these names, and HCL will not accept a
    # hyphenated bare key. The names match GATES in attack/end_to_end.py
    # exactly -- if they ever drift, the attack silently reads every control as
    # absent and reports a breach you did not actually have.
    "guardrail"         = var.guardrail_enabled
    "goal-lock"         = var.goal_lock_enabled
    "tool-least-priv"   = var.tool_least_priv_enabled
    "hitl-approval"     = var.hitl_approval_enabled
    "run-audit"         = var.run_audit_enabled
    "foundation-pinned" = true
  })
}
