variable "project" {
  type    = string
  default = "hwz"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "mcp_authenticated" {
  description = "Require auth (token/mTLS) on the MCP server and keep it private. Off in baseline."
  type        = bool
  default     = false
}

variable "tool_least_priv" {
  description = "Give each tool its own least-privilege role instead of the model's broad role. Off in baseline."
  type        = bool
  default     = false
}

variable "tool_allowlist" {
  description = "Enforce the registered-tool allowlist + argument schema at dispatch. Off in baseline."
  type        = bool
  default     = false
}

variable "egress_locked" {
  description = "Lock tool egress to VPC endpoints / allowlist (kills SSRF). Off in baseline."
  type        = bool
  default     = false
}

variable "toolcall_guardrail" {
  description = "Wire the tool-call guardrail (call + result) in front of every tool. Off in baseline."
  type        = bool
  default     = false
}
