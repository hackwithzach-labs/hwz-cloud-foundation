# -----------------------------------------------------------------------------
# Per-tool least-privilege roles for the agent loop, Module 6 (Pillar 3).
#
# Pillar 2 gave each TOOL its own role. Pillar 3 runs those tools in a LOOP, so
# the blast radius of a shared broad role is worse: one hijacked step can spend
# every permission the whole chain holds. The control is the same, and it
# matters more here.
#
#   tool_least_priv = true   -> each tool assumes its OWN scoped role
#   tool_least_priv = false  -> the whole agent shares one broad role (weak)
# -----------------------------------------------------------------------------

variable "tool_least_priv" {
  type    = bool
  default = false
}

variable "name_prefix" {
  type    = string
  default = "hwz"
}

locals {
  scoped = var.tool_least_priv ? 1 : 0
  broad  = var.tool_least_priv ? 0 : 1
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# SCOPED: the read-only research tool can read one table, nothing else.
resource "aws_iam_role" "tool_research" {
  count              = local.scoped
  name               = "${var.name_prefix}-agent-tool-research"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "tool_research" {
  count = local.scoped
  name  = "read-only"
  role  = aws_iam_role.tool_research[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["dynamodb:GetItem", "dynamodb:Query"]
      Resource = "*"
    }]
  })
}

# SCOPED: the notify tool can only send email through SES.
resource "aws_iam_role" "tool_notify" {
  count              = local.scoped
  name               = "${var.name_prefix}-agent-tool-notify"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "tool_notify" {
  count = local.scoped
  name  = "ses-send-only"
  role  = aws_iam_role.tool_notify[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ses:SendEmail"]
      Resource = "*"
    }]
  })
}

# BROAD (the weak default): one shared role the whole loop runs under. In an
# agent this is the give-it-everything anti-pattern at its most dangerous: the
# loop can chain any of these permissions across steps with no human in the way.
resource "aws_iam_role" "agent_shared_broad" {
  count              = local.broad
  name               = "${var.name_prefix}-agent-shared-broad"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "agent_shared_broad" {
  count = local.broad
  name  = "too-broad"
  role  = aws_iam_role.agent_shared_broad[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["dynamodb:*", "ses:*", "s3:*", "secretsmanager:*", "lambda:*"]
      Resource = "*"
    }]
  })
}

output "least_priv_enabled" {
  value = var.tool_least_priv
}
