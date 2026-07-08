variable "name_prefix" {
  type = string
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "multi_region" {
  type    = bool
  default = false
}

variable "log_file_validation" {
  type    = bool
  default = false
}

variable "data_events" {
  type    = bool
  default = false
}

variable "use_kms" {
  type    = bool
  default = false
}

variable "kms_key_arn" {
  type    = string
  default = ""
}
