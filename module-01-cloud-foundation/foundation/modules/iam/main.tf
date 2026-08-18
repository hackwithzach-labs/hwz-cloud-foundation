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
  broad_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "BroadServiceAccess"
      Effect   = "Allow"
      Action   = ["s3:*", "secretsmanager:*", "kms:*", "bedrock:*", "logs:*", "cloudtrail:LookupEvents"]
      Resource = "*"
    }]
  })

  scoped_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "S3ProjectData",  Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"], Resource = ["arn:aws:s3:::${var.name_prefix}-*", "arn:aws:s3:::${var.name_prefix}-*/*"] },
      { Sid = "SecretsProject", Effect = "Allow", Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"], Resource = ["arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}-*"] },
      { Sid = "KmsProject",     Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"], Resource = ["arn:aws:kms:${var.region}:${var.account_id}:key/*"] },
      { Sid = "LogsProject",    Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"], Resource = ["arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.name_prefix}-*"] },
      { Sid = "BedrockInvoke",  Effect = "Allow", Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], Resource = ["*"] },
      { Sid = "CloudTrailRead", Effect = "Allow", Action = ["cloudtrail:LookupEvents"], Resource = ["*"] }
    ]
  })
}

resource "aws_iam_role_policy" "workload_grant" {
  name   = "${var.name_prefix}-workload-grant"
  role   = aws_iam_role.workload.id
  policy = var.scope_workload ? local.scoped_policy : local.broad_policy
}

resource "aws_iam_role_policy" "deny_destructive" {
  count = var.deny_destructive ? 1 : 0
  name  = "${var.name_prefix}-deny-destructive"
  role  = aws_iam_role.workload.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DenyDestructive"
      Effect   = "Deny"
      Action   = ["s3:DeleteBucket", "s3:PutBucketPolicy", "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "kms:ScheduleKeyDeletion", "kms:DisableKey", "secretsmanager:DeleteSecret"]
      Resource = "*"
    }]
  })
}
