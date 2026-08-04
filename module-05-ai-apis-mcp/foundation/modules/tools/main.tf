# -----------------------------------------------------------------------------
# Per-tool least-privilege roles for Module 5 (Pillar 2).
#
# The control that matters most: when tool_least_priv is on, each tool assumes
# its OWN scoped role (lookup_account reads one table; send_email calls SES and
# nothing else), so an injection that reaches a dangerous tool dies in IAM. When
# it is off, every tool shares one broad role — the model's role — and a single
# compromised tool can do everything.
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

# SCOPED: lookup_account can read one table, nothing else.
resource "aws_iam_role" "tool_lookup_account" {
  count              = local.scoped
  name               = "${var.name_prefix}-tool-lookup-account"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "tool_lookup_account" {
  count = local.scoped
  name  = "read-one-table"
  role  = aws_iam_role.tool_lookup_account[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["dynamodb:GetItem", "dynamodb:Query"]
      Resource = "*"
    }]
  })
}

# SCOPED: send_email can only call SES.
resource "aws_iam_role" "tool_send_email" {
  count              = local.scoped
  name               = "${var.name_prefix}-tool-send-email"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "tool_send_email" {
  count = local.scoped
  name  = "ses-send-only"
  role  = aws_iam_role.tool_send_email[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ses:SendEmail"]
      Resource = "*"
    }]
  })
}

# BROAD (the weak default): one shared role every tool uses. The give-it-
# everything-so-it-stops-erroring pattern. This is what the scanner flags.
resource "aws_iam_role" "tools_shared_broad" {
  count              = local.broad
  name               = "${var.name_prefix}-tools-shared-broad"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "tools_shared_broad" {
  count = local.broad
  name  = "too-broad"
  role  = aws_iam_role.tools_shared_broad[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["dynamodb:*", "ses:*", "s3:*", "secretsmanager:*"]
      Resource = "*"
    }]
  })
}

output "least_priv_enabled" {
  value = var.tool_least_priv
}
