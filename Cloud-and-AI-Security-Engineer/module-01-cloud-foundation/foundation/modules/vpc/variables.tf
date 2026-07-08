variable "name_prefix" { type = string }
variable "vpc_cidr" { type = string }
variable "azs" { type = list(string) }
variable "public_subnet_cidrs" { type = list(string) }
variable "private_subnet_cidrs" { type = list(string) }

variable "endpoint_ingress_cidr" {
  description = "CIDR allowed to reach interface endpoints on 443. Weak=0.0.0.0/0."
  type        = string
}

variable "enable_flow_logs" {
  type    = bool
  default = false
}

variable "flow_logs_group_arn" {
  description = "CloudWatch log group ARN for flow logs. Comes from the observability module."
  type        = string
  default     = ""
}

variable "flow_logs_role_arn" {
  description = "IAM role ARN VPC Flow Logs assumes to write to CloudWatch."
  type        = string
  default     = ""
}
