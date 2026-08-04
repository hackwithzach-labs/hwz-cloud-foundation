variable "project" {
  description = "Project prefix for all resource names."
  type        = string
  default     = "hwz"
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "guardrails_enabled" {
  description = "Turn the LLM guardrail (input + output filters, data/instruction boundary) on. Off in baseline, on in hardened."
  type        = bool
  default     = false
}

variable "waf_enabled" {
  description = "Turn the AWS WAF on the API edge on. Off in baseline, on in hardened."
  type        = bool
  default     = false
}

variable "rate_limit" {
  description = "WAF rate-based rule: requests per IP per 5 minutes."
  type        = number
  default     = 2000
}

variable "api_resource_arn" {
  description = "ARN of the API's ALB / API Gateway stage to protect. Empty = create the ACL only (lab default)."
  type        = string
  default     = ""
}
