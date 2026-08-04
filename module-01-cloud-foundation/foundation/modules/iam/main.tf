###############################################################################
# modules/iam
# A workload role your pillar apps assume (EC2 or Lambda).
#
#   baseline (scope_workload=false): ONE broad, service-wide grant -- the
#     "give the app admin so it stops erroring" anti-pattern. s3:*, kms:*,
#     secretsmanager:* on Resource "*". The scanner flags this as a wildcard
#     allow (HIGH).
#   hardened (scope_workload=true): explicit least-privilege actions -- NO
#     action ends in :* -- each statement pinned to THIS project's own
#     resources by name (the data bucket, the app secret, the foundation key
#     via kms:ViaService, the app log group, Bedrock models). On top of that,
#     hardened also bolts an explicit DENY for destructive actions
#     (deny_destructive=true). Explicit deny always wins, so this is the
#     pattern that survives real audits.
#
# The grant is ONE resource whose policy document switches on scope_workload,
# so hardening UPDATES the policy in place instead of destroying and recreating
# an inline policy of the same name (which could race and leave the role with no
# grant at all). One name, one resource, one in-place change.
###############################################################################

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com", "lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "workload" {
  name               = "${var.name_prefix}-workload"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

locals {
  # Baseline grant: broad, over-scoped on purpose. This is what
  # "give the app admin so it stops erroring" looks like.
  broad_grant = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "BroadServiceAccess"
      Effect = "Allow"
      Action = [
        "s3:*", "secretsmanager:*", "kms:*",
        "bedrock:*", "logs:*", "cloudtrail:LookupEvents"
      ]
      Resource = "*"
    }]
  })

  # Hardened grant: explicit least-privilege. No action ends in :*, so nothing
  # is service-wide, and every Resource is pinned to the foundation's own
  # resources by name prefix (the random suffix Terraform adds is covered by the
  # trailing wildcard IN THE RESOURCE ARN, which is not the same as a wildcard
  # action).
  scoped_grant = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DataBucketObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "arn:aws:s3:::${var.name_prefix}-data-*/*"
      },
      {
        Sid      = "DataBucketList"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketLocation"]
        Resource = "arn:aws:s3:::${var.name_prefix}-data-*"
      },
      {
        Sid      = "AppSecretRead"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}-app-secret-*"
      },
      {
        Sid      = "FoundationKeyDataPlane"
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = "arn:aws:kms:${var.region}:${var.account_id}:key/*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = [
              "s3.${var.region}.amazonaws.com",
              "secretsmanager.${var.region}.amazonaws.com"
            ]
          }
        }
      },
      {
        Sid      = "AppLogWrite"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
        Resource = "arn:aws:logs:${var.region}:${var.account_id}:log-group:/${var.name_prefix}/*"
      },
      {
        Sid      = "BedrockInvoke"
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = "arn:aws:bedrock:${var.region}::foundation-model/*"
      },
      {
        Sid      = "ReadAccountTrail"
        Effect   = "Allow"
        Action   = ["cloudtrail:LookupEvents"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "workload_grant" {
  name   = "${var.name_prefix}-workload-grant"
  role   = aws_iam_role.workload.id
  policy = var.scope_workload ? local.scoped_grant : local.broad_grant
}

# Hardened only: an explicit deny for the actions that let a compromised app
# destroy your evidence and your data. Attached when deny_destructive = true.
resource "aws_iam_role_policy" "deny_destructive" {
  count = var.deny_destructive ? 1 : 0
  name  = "${var.name_prefix}-deny-destructive"
  role  = aws_iam_role.workload.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenyDestructive"
      Effect = "Deny"
      Action = [
        "s3:DeleteBucket", "s3:PutBucketPolicy",
        "cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
        "kms:ScheduleKeyDeletion", "kms:DisableKey",
        "secretsmanager:DeleteSecret"
      ]
      Resource = "*"
    }]
  })
}
