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
  description = "The foundation app log group. Always watched, because the EC2 CloudWatch agent ships into it."
  type        = string
}

variable "watched_log_groups" {
  description = "Every OTHER log group a deployed producer actually delivers into -- the Lambda service group, the container awslogs group. The producers module computes this list; the detection module attaches the app-layer metric filters to each entry. A group missing from this list is a producer nobody is counting, which is the exact failure this module teaches: the filters look perfect and the detection is blind."
  type        = list(string)
  default     = []
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
