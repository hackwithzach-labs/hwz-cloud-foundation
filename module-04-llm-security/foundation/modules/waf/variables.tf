variable "waf_enabled" {
  description = "Master switch for the AWS WAF on the API edge. Off in baseline, on in hardened."
  type        = bool
  default     = false
}

variable "name_prefix" {
  description = "Prefix for WAF resource names."
  type        = string
  default     = "hwz"
}

variable "rate_limit" {
  description = "Requests per 5-minute window per IP before the rate-based rule blocks."
  type        = number
  default     = 2000
}

variable "associate_resource_arn" {
  description = "ARN of the ALB / API Gateway stage to attach the web ACL to. Empty = create ACL only."
  type        = string
  default     = ""
}

variable "log_group_arn" {
  description = "CloudWatch Logs group ARN for WAF logs (feeds the Module 3 detection layer). Empty = no logging config."
  type        = string
  default     = ""
}
