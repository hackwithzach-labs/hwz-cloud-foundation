###############################################################################
# variables.tf  (ROOT)
#
# Two kinds of variable live here:
#   1. Identity + networking values (project, region, CIDRs). Same in every run.
#   2. SECURITY POSTURE FLAGS. These are the whole point of the course.
#      In baseline.tfvars every flag is set to its WEAK value on purpose.
#      In hardened.tfvars every flag flips to its STRONG value.
#      You break it, then you harden it, using the same code.
###############################################################################

# ---------------------------------------------------------------------------
# 1. Identity + networking
# ---------------------------------------------------------------------------

variable "project" {
  description = "Short prefix for every resource name. Lowercase, no spaces."
  type        = string
  default     = "hwz"
}

variable "environment" {
  description = "Environment label used in tags and names (lab, dev, prod)."
  type        = string
  default     = "lab"
}

variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the foundation VPC."
  type        = string
  default     = "10.20.0.0/16"
}

variable "azs" {
  description = "Availability zones to spread subnets across. Two is enough for the lab."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "public_subnet_cidrs" {
  description = "One public subnet CIDR per AZ."
  type        = list(string)
  default     = ["10.20.0.0/24", "10.20.1.0/24"]
}

variable "private_subnet_cidrs" {
  description = "One private subnet CIDR per AZ. Pillar 2 (Bedrock) attaches its VPC endpoint here."
  type        = list(string)
  default     = ["10.20.10.0/24", "10.20.11.0/24"]
}

variable "log_retention_days" {
  description = "CloudWatch log group retention. Short in the lab to keep cost down."
  type        = number
  default     = 14
}

# ---------------------------------------------------------------------------
# 2. Security posture flags  (weak in baseline.tfvars, strong in hardened.tfvars)
# ---------------------------------------------------------------------------

variable "ssh_ingress_cidr" {
  description = "Who can reach the endpoint security group on 443/22. WEAK = 0.0.0.0/0. STRONG = the VPC CIDR or your IP."
  type        = string
  default     = "0.0.0.0/0"
}

variable "vpc_flow_logs" {
  description = "Capture VPC flow logs to CloudWatch. WEAK = false (you are blind). STRONG = true."
  type        = bool
  default     = false
}

variable "s3_block_public_access" {
  description = "Attach an S3 Block Public Access config to the data bucket. WEAK = false. STRONG = true."
  type        = bool
  default     = false
}

variable "s3_default_encryption" {
  description = "Turn on default server-side encryption on the data bucket. WEAK = false. STRONG = true (KMS)."
  type        = bool
  default     = false
}

variable "s3_enforce_tls" {
  description = "Attach a bucket policy that denies any non-TLS request. WEAK = false. STRONG = true."
  type        = bool
  default     = false
}

variable "s3_versioning" {
  description = "Enable object versioning on the data bucket. WEAK = false. STRONG = true."
  type        = bool
  default     = false
}

variable "kms_strict_key_policy" {
  description = "Scope the KMS key policy to specific principals. WEAK = false (broad). STRONG = true."
  type        = bool
  default     = false
}

variable "kms_allow_cloudtrail" {
  description = "Add the CloudTrail service statement to the KMS key policy so the trail can encrypt logs. Set true whenever cloudtrail_use_kms is true."
  type        = bool
  default     = false
}

variable "iam_deny_destructive" {
  description = "Attach a deny policy blocking destructive actions to the workload role. WEAK = false. STRONG = true."
  type        = bool
  default     = false
}

variable "cloudtrail_multi_region" {
  description = "Make the trail multi-region. WEAK = false. STRONG = true."
  type        = bool
  default     = false
}

variable "cloudtrail_log_file_validation" {
  description = "Enable CloudTrail log file (digest) validation. WEAK = false. STRONG = true."
  type        = bool
  default     = false
}

variable "cloudtrail_data_events" {
  description = "Record S3 object-level (data) events. WEAK = false (you miss the read/write of objects). STRONG = true."
  type        = bool
  default     = false
}

variable "cloudtrail_use_kms" {
  description = "Encrypt CloudTrail logs with the foundation KMS key. WEAK = false. STRONG = true. Requires kms_allow_cloudtrail = true."
  type        = bool
  default     = false
}

variable "iam_scope_workload" {
  type    = bool
  default = false
}
