variable "name_prefix" { type = string }

variable "deny_destructive" {
  type    = bool
  default = false
}

variable "scope_workload" {
  type    = bool
  default = false
}

variable "account_id" { type = string }
variable "region"     { type = string }
