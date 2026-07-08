variable "name_prefix" { type = string }

variable "deny_destructive" {
  description = "Weak=false (role can delete anything it can touch). Strong=true (attach an explicit deny for destructive actions)."
  type        = bool
  default     = false
}
