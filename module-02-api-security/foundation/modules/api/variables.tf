###############################################################################
# modules/api :: variables.tf
#
# Everything this layer needs from the foundation arrives as an explicit input.
# The child module never reaches back into module.foundation itself -- that is
# what makes it reusable by Chapters 11, 12, 13 and the capstone.
###############################################################################

variable "name_prefix" {
  description = "Name prefix, e.g. hwz-lab."
  type        = string
}

variable "project" {
  description = "Project tag applied to every resource."
  type        = string
}

variable "region" {
  description = "Region the lab runs in. Used to build the Bedrock service name and model ARN."
  type        = string
}

variable "vpc_id" {
  description = "Foundation VPC id."
  type        = string
}

variable "private_subnet_ids" {
  description = "Foundation private subnets. The Bedrock interface endpoint lands here, so the model has no public path."
  type        = list(string)
}

variable "endpoint_security_group_id" {
  description = "Foundation security group for interface endpoints (443 from inside the VPC)."
  type        = string
}

variable "secret_arn" {
  description = "Foundation Secrets Manager ARN. The API role is scoped to read this one secret and nothing else."
  type        = string
}

variable "allowed_model" {
  description = "The single Bedrock foundation model the API role may invoke. One model, not a wildcard: an over-broad bedrock:InvokeModel is how a compromised app starts calling models you never budgeted for. Claude 3 Haiku (the old default) reached end of life on Bedrock in us-east-1 on Sep 10, 2026."
  type        = string
  default     = "anthropic.claude-haiku-5-5"
}

variable "inference_geo" {
  description = "Prefix of the cross-Region inference profile the app calls: us, eu, apac or global. The app's model id is <geo>.<allowed_model>."
  type        = string
  default     = "us"
}

variable "inference_regions" {
  description = "Every Region the inference profile can route to. The model must be allowed in each, or calls fail at random with AccessDenied. The us profile from us-east-1 routes to these three."
  type        = list(string)
  default     = ["us-east-1", "us-east-2", "us-west-2"]
}
