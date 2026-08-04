variable "name_prefix" {
  description = "Project-environment prefix, e.g. hwz-lab. All detection resources are named from it so hwz-detect can scope to the lab."
  type        = string
}

variable "project" {
  description = "Project tag applied to every resource."
  type        = string
}

variable "account_id" {
  description = "The AWS account id, used in ARNs and Config/GuardDuty scoping."
  type        = string
}

variable "region" {
  description = "The region the lab runs in."
  type        = string
}

variable "app_log_group_name" {
  description = "The foundation app log group the API writes structured audit lines to. Metric filters attach here."
  type        = string
}

variable "cloudtrail_bucket_arn" {
  description = "ARN of the foundation CloudTrail S3 bucket, referenced when teaching Athena history. Not modified here."
  type        = string
  default     = ""
}

variable "detections_enabled" {
  description = "The weak/hardened switch for the DETECTION layer. false = blind (nothing wired), true = the full SOC comes up. The foundation underneath is always hardened."
  type        = bool
  default     = false
}

variable "alert_email" {
  description = "Where alerts go. The STUDENT sets this to their own email; AWS sends a confirmation link they must click. Left empty, no subscription is created and hwz-detect will flag the alert path as unconfirmed."
  type        = string
  default     = ""
}
