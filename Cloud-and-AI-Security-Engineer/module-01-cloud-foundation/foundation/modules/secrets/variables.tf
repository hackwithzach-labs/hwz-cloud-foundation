variable "name_prefix" {
  type = string
}

variable "kms_key_arn" {
  description = "KMS key used to encrypt the secret. Empty string = AWS-managed key."
  type        = string
  default     = ""
}
