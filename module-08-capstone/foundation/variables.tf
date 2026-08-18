# module-08-capstone :: foundation/variables.tf
#
# One switch per pillar. baseline.tfvars turns them all off, hardened.tfvars
# turns them all on, and attack/end_to_end.py reads the posture file this root
# writes -- so the attack always reflects what you actually deployed, not what
# you meant to deploy.

variable "project" {
  description = "Name prefix for every resource."
  type        = string
  default     = "hwz"
}

variable "environment" {
  description = "Environment suffix. Must match the value used in modules 1-3."
  type        = string
  default     = "lab"
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "guardrail_enabled" {
  description = "Pillar 1 (ch11): input/output guardrail around the model call."
  type        = bool
  default     = false
}

variable "goal_lock_enabled" {
  description = "Pillar 3 (ch13): the standing objective is not model-editable."
  type        = bool
  default     = false
}

variable "tool_least_priv_enabled" {
  description = "Pillar 2 (ch12): each tool role bound to the session identity."
  type        = bool
  default     = false
}

variable "hitl_approval_enabled" {
  description = "Pillar 3 (ch13): a human gates every irreversible action."
  type        = bool
  default     = false
}

variable "run_audit_enabled" {
  description = "Pillar 1 (ch10): agent decisions reach the SOC."
  type        = bool
  default     = false
}

variable "allowed_model" {
  type    = string
  default = "anthropic.claude-3-haiku-20240307-v1:0"
}
