variable "name_prefix" {
  type = string
}

variable "retention_days" {
  type    = number
  default = 14
}

variable "deny_destructive" {
  description = "Attach an explicit deny for destructive actions to the flow logs role. The scanner checks EVERY project-prefixed role for a destructive deny, not just the workload role. WEAK = false. STRONG = true."
  type        = bool
  default     = false
}
