variable "name_prefix" {
  type = string
}

variable "block_public_access" {
  type    = bool
  default = false
}

variable "default_encryption" {
  type    = bool
  default = false
}

variable "kms_key_arn" {
  type    = string
  default = ""
}

variable "enforce_tls" {
  type    = bool
  default = false
}

variable "versioning" {
  type    = bool
  default = false
}
