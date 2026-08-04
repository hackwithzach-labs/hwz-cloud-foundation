variable "name_prefix" { type = string }

variable "deny_destructive" {
  description = "Weak=false (role can delete anything it can touch). Strong=true (attach an explicit deny for destructive actions)."
  type        = bool
  default     = false
}

variable "scope_workload" {
  description = "Weak=false (one broad service-wide grant: s3:*, kms:*, secretsmanager:*). Strong=true (explicit least-privilege actions, no wildcards, scoped to THIS project's own resources by name)."
  type        = bool
  default     = false
}

variable "account_id" {
  description = "Account id, used to build scoped resource ARNs when scope_workload = true."
  type        = string
  default     = ""
}

variable "region" {
  description = "Region, used to build scoped resource ARNs when scope_workload = true."
  type        = string
  default     = ""
}
