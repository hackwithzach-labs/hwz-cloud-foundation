variable "project" {
  type    = string
  default = "hwz"
}

variable "environment" {
  type    = string
  default = "lab"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

# --- the six agent-loop controls. WEAK = false, STRONG = true. ---------------

variable "goal_locked" {
  description = "Pin the agent's goal so injected content cannot redirect the run mid-loop."
  type        = bool
  default     = false
}

variable "memory_guardrail" {
  description = "Vet every memory write so a poisoned note cannot fire on a later step."
  type        = bool
  default     = false
}

variable "tool_least_priv" {
  description = "Give each tool its own scoped role instead of one broad role for the whole loop."
  type        = bool
  default     = false
}

variable "step_budget" {
  description = "Bound the loop with a per-run step/tool-call cap."
  type        = bool
  default     = false
}

variable "hitl_approval" {
  description = "Require human approval before any high-impact/irreversible action fires."
  type        = bool
  default     = false
}

variable "run_audit" {
  description = "Emit every agent step and decision to the Chapter 10 SOC."
  type        = bool
  default     = false
}
