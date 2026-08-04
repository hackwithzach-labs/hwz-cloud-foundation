###############################################################################
# modules/kms
# One customer-managed key the whole foundation shares. The KEY POLICY is where
# the lesson lives. Baseline = broad (root can do anything, no CloudTrail grant).
# Hardened = scoped to the workload role AND grants CloudTrail so encrypted
# trail logs actually work. The old course was missing this CloudTrail grant,
# which is why turning on trail encryption blew up.
###############################################################################

locals {
  root_arn = "arn:aws:iam::${var.account_id}:root"

  # Baseline: the classic wide-open key policy. Root account has full control.
  baseline_statements = [
    {
      Sid       = "EnableRoot"
      Effect    = "Allow"
      Principal = { AWS = local.root_arn }
      Action    = "kms:*"
      Resource  = "*"
    }
  ]

  # Hardened: root keeps admin, the workload role gets data-plane use only.
  strict_statements = [
    {
      # The account root keeps full control of ITS OWN key. This is the standard
      # AWS "Enable IAM User Permissions" statement, and AWS explicitly warns
      # against removing it: doing so locks the account out of its own key. The
      # earlier version of this policy listed only admin actions and dropped
      # kms:Decrypt / kms:GenerateDataKey -- which locked root (and Terraform,
      # which runs as root) out of reading the KMS-encrypted secret, so every
      # subsequent apply failed at refresh with "Access to KMS is not allowed".
      # Root access here is not "broad": it is still gated by IAM. Least
      # privilege for WORKLOADS is enforced by the scoped WorkloadUse statement
      # below, which is where that lesson belongs.
      Sid       = "EnableRootAccount"
      Effect    = "Allow"
      Principal = { AWS = local.root_arn }
      Action    = "kms:*"
      Resource  = "*"
    },
    {
      Sid       = "WorkloadUse"
      Effect    = "Allow"
      Principal = { AWS = var.workload_role_arn != "" ? var.workload_role_arn : local.root_arn }
      Action = [
        "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
        "kms:GenerateDataKey*", "kms:DescribeKey"
      ]
      Resource = "*"
    }
  ]

  # CloudTrail grant, added to whichever base we picked when allow_cloudtrail=true.
  cloudtrail_statement = {
    Sid       = "AllowCloudTrailEncrypt"
    Effect    = "Allow"
    Principal = { Service = "cloudtrail.amazonaws.com" }
    Action    = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    Resource  = "*"
    Condition = {
      StringLike = {
        "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${var.account_id}:trail/*"
      }
    }
  }

  # Terraform requires both arms of a conditional to be the same type, and these
  # statement lists differ in length and shape on purpose. The concat-with-empty
  # pattern below picks one list without ever asking Terraform to unify them.
  base_statements = concat(
    var.strict_key_policy ? [] : local.baseline_statements,
    var.strict_key_policy ? local.strict_statements : [],
  )
  all_statements = concat(
    local.base_statements,
    var.allow_cloudtrail ? [local.cloudtrail_statement] : [],
  )
}

resource "aws_kms_key" "this" {
  description             = "${var.name_prefix} foundation key"
  deletion_window_in_days = 7
  enable_key_rotation     = var.strict_key_policy # rotation on when hardened

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = local.all_statements
  })
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name_prefix}-foundation"
  target_key_id = aws_kms_key.this.key_id
}
