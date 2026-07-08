###############################################################################
# modules/iam
# A workload role your pillar apps assume (EC2 or Lambda). In baseline it holds
# a wildcard-ish policy: "give it what it needs and we'll tighten later" (we
# never do). In hardened we bolt an explicit DENY for destructive actions on
# top. Explicit deny always wins, so this is the pattern that survives real
# audits.
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

# Baseline grant: broad access to the services the pillars touch. Over-scoped
# on purpose. This is what "give the app admin so it stops erroring" looks like.
resource "aws_iam_role_policy" "workload_grant" {
  name = "${var.name_prefix}-workload-grant"
  role = aws_iam_role.workload.id

  policy = jsonencode({
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
