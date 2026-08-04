variable "project" {
  description = "Project tag / name prefix that scopes the lab. hwz-detect reads the same value."
  type        = string
  default     = "hwz"
}

variable "environment" {
  description = "Environment suffix, e.g. lab."
  type        = string
  default     = "lab"
}

variable "region" {
  description = "Region the lab runs in."
  type        = string
  default     = "us-east-1"
}

variable "detections_enabled" {
  description = "The weak/hardened switch for the detection layer. Set by the tfvars files: false in baseline, true in hardened."
  type        = bool
  default     = false
}

variable "alert_email" {
  description = "YOUR email. AWS sends a confirmation link you must click before any alert is delivered. Set it in hardened.tfvars or with -var. Left empty, the SOC deploys but has no confirmed alert path and hwz-detect flags it."
  type        = string
  default     = ""
}
