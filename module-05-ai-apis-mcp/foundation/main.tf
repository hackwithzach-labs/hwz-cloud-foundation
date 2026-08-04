# -----------------------------------------------------------------------------
# Module 5: AI APIs and MCP (Pillar 2) — root composition.
#
# Same pattern as every pillar: the Ch8 foundation and the Ch9 API deploy PINNED
# HARDENED; only THIS pillar's new layer — the MCP server and the tools — starts
# weak, gated on the five flags. One apply at session start, one destroy at the
# end.
# -----------------------------------------------------------------------------

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

# The Ch8 foundation + Ch9 API, pinned hardened (composed on the course machine):
# module "foundation" { source = "../../module-01-cloud-foundation/foundation" ... }
# module "api"        { source = "../../module-02-api-security/foundation" ... }

# THIS pillar's new layer: per-tool least-privilege roles.
module "tools" {
  source          = "./modules/tools"
  tool_least_priv = var.tool_least_priv
  name_prefix     = var.project
}

# The MCP server, the tool allowlist, the egress locking, and the tool-call
# guardrail are wired in the app + network layer the module ships; their state
# is recorded here so scan/scan.py reflects the deployed reality and the
# deploy -> scan -> harden -> scan loop is honest end to end.
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
  value = module.tools.least_priv_enabled
}
