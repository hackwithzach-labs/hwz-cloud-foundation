# -----------------------------------------------------------------------------
# Module 4: LLM Security (Pillar 1) — root composition.
#
# Same pattern as every pillar from Chapter 8 on: the foundation modules deploy
# PINNED HARDENED (you proved them in Ch8), the Chapter 9 API composes on top,
# and only THIS pillar's new layer — the guardrail and the WAF — starts weak,
# gated on guardrails_enabled / waf_enabled.
#
# NOTE: the module.foundation and module.api sources below reference the
# Module 1 / Module 2 codebases. On the course machine they resolve to the
# sibling module repos; here they document the composition. Run
# `terraform init && terraform validate` on a machine with the AWS provider.
# -----------------------------------------------------------------------------

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    local = {
      source  = "hashicorp/local"
      version = ">= 2.4"
    }
  }
}

provider "aws" {
  region = var.region
}

# The Chapter 8 foundation, pinned hardened. Nothing here is re-weakened.
# module "foundation" {
#   source = "../../module-01-cloud-foundation/foundation"
#   # ...hardened inputs...
# }

# The Chapter 9 inference API, composed on the hardened foundation.
# module "api" {
#   source            = "../../module-02-api-security/foundation"
#   # ...pinned hardened...
# }

# THIS pillar's new layer #1: the AWS WAF on the API edge.
module "waf" {
  source      = "./modules/waf"
  waf_enabled = var.waf_enabled
  name_prefix = var.project
  rate_limit  = var.rate_limit

  # Wire these to the API + Module 3 log group on the course machine:
  associate_resource_arn = var.api_resource_arn
  # log_group_arn        = module.foundation.app_log_group_arn
}

# THIS pillar's new layer #2: the guardrail. The guardrail runs in the API
# process (guard.py), so its "deployment" here is the posture flag the app and
# the scanner read. We emit a posture file so `scan/scan.py` reflects the real
# state of the deployed stack and the deploy -> scan -> harden -> scan loop is
# honest end to end.
resource "local_file" "posture" {
  filename = "${path.module}/../scan/posture.json"
  content = jsonencode({
    input_guardrail            = var.guardrails_enabled
    output_guardrail           = var.guardrails_enabled
    instruction_data_boundary  = var.guardrails_enabled
    waf_web_acl                = var.waf_enabled
    waf_rate_rule              = var.waf_enabled
  })
}

output "guardrails_enabled" {
  value = var.guardrails_enabled
}

output "waf_web_acl_arn" {
  value = module.waf.web_acl_arn
}
