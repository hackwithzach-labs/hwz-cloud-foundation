# -----------------------------------------------------------------------------
# Module 6: Agentic AI (Pillar 3) — root composition.
#
# Same pattern as every pillar: the Ch8 foundation, the Ch9 API, and the Ch12
# MCP + tools deploy PINNED HARDENED (you proved them already). Only THIS
# pillar's new layer — the AGENT LOOP and its controls — starts weak, gated on
# the six flags. One apply at session start, one destroy at the end.
#
# The loop controls (goal lock, memory guardrail, step budget, human approval,
# run audit) live in the agent RUNTIME (agentguard.py + the orchestrator), so
# their deployment here is the posture the app and the scanner read. The one
# thing that is pure infrastructure — each tool's own least-privilege role —
# is the ./modules/agent control below, carried forward from Pillar 2.
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

# The Ch8 foundation + Ch9 API + Ch12 tools, pinned hardened (composed on the
# course machine):
# module "foundation" { source = "../../module-01-cloud-foundation/foundation" ... }
# module "api"        { source = "../../module-02-api-security/foundation" ... }
# module "mcp"        { source = "../../module-05-ai-apis-mcp/foundation" ... }

# THIS pillar's infrastructure control: the agent's tool roles. When
# tool_least_priv is on, each tool the agent can call assumes its OWN scoped
# role, so a hijacked step cannot cascade beyond that one tool's job. When off,
# the whole loop runs under one broad role and excessive agency compounds.
module "agent" {
  source          = "./modules/agent"
  tool_least_priv = var.tool_least_priv
  name_prefix     = var.project
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
  value = module.agent.least_priv_enabled
}
