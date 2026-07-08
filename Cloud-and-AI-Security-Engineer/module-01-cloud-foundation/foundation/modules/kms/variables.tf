variable "name_prefix" { type = string }
variable "account_id" { type = string }
variable "region" { type = string }

variable "strict_key_policy" {
  description = "Weak=false (broad root policy). Strong=true (scoped to the workload role + admins)."
  type        = bool
  default     = false
}

variable "allow_cloudtrail" {
  description = "Add the CloudTrail service statement so the trail can encrypt logs with this key."
  type        = bool
  default     = false
}

variable "workload_role_arn" {
  description = "The workload role that should be allowed to use the key when the policy is strict."
  type        = string
  default     = ""
}
