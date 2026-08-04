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

variable "enforce_tls" {
  description = "Add a deny-non-TLS (aws:SecureTransport=false) statement to the trail log bucket policy. WEAK = false. STRONG = true."
  type        = bool
  default     = false
}

variable "versioning" {
  description = "Enable versioning on the trail log bucket so log objects survive overwrite/delete. WEAK = false. STRONG = true."
  type        = bool
  default     = false
}
