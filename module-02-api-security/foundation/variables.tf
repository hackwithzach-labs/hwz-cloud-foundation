###############################################################################
# module-02-api-security :: foundation/variables.tf
#
# Note what is NOT here: no foundation weakness flags. This root does not let
# you weaken the foundation. It exposes only Pillar-2 knobs. The weak/hardened
# choice for THIS module lives in the app (app/config.py, HWZ_PROFILE).
###############################################################################

variable "project" {
  type    = string
  default = "hwz"
}

variable "environment" {
  type    = string
  default = "lab"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "allowed_model" {
  description = "The single Bedrock foundation model the API role may invoke."
  type        = string
  default     = "anthropic.claude-3-haiku-20240307-v1:0"
}
