###############################################################################
# modules/observability
# The CloudWatch log group your apps write to, plus the IAM role VPC Flow Logs
# needs to publish into it. The VPC module points its flow logs at these when
# vpc_flow_logs = true. Kept in its own module so any pillar can consume logging
# without pulling in the whole foundation.
###############################################################################

resource "aws_cloudwatch_log_group" "app" {
  name              = "/${var.name_prefix}/app"
  retention_in_days = var.retention_days
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/${var.name_prefix}/vpc-flow"
  retention_in_days = var.retention_days
}

# Role that the VPC Flow Logs service assumes to write into the flow log group.
data "aws_iam_policy_document" "flow_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow" {
  name               = "${var.name_prefix}-flowlogs"
  assume_role_policy = data.aws_iam_policy_document.flow_assume.json
}

resource "aws_iam_role_policy" "flow" {
  name = "${var.name_prefix}-flowlogs"
  role = aws_iam_role.flow.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "${aws_cloudwatch_log_group.flow.arn}:*"
    }]
  })
}

# Hardened only: the flow logs role is a project-prefixed role too, so the
# scanner holds it to the same standard as the workload role -- it must carry an
# explicit deny on destructive actions. This role only ever needs to write logs,
# so denying data/evidence destruction costs it nothing and closes the finding.
resource "aws_iam_role_policy" "flow_deny" {
  count = var.deny_destructive ? 1 : 0
  name  = "${var.name_prefix}-flowlogs-deny"
  role  = aws_iam_role.flow.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenyDestructive"
      Effect = "Deny"
      Action = [
        "s3:DeleteBucket", "s3:PutBucketPolicy",
        "cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
        "kms:ScheduleKeyDeletion", "kms:DisableKey",
        "secretsmanager:DeleteSecret", "logs:DeleteLogGroup"
      ]
      Resource = "*"
    }]
  })
}
