###############################################################################
# modules/api :: the Chapter 9 API layer, as a REUSABLE CHILD MODULE
#
# WHY THIS FILE EXISTS
#
# These three resources used to live directly in module-02's root. That worked
# for Chapter 9 and only Chapter 9. The moment Chapters 11, 12, 13 and the
# capstone needed "the foundation plus the API," their only option was to call
# module-02's ROOT -- a module that carries its own `provider` block. Roots
# calling roots calling roots is legal Terraform and a genuinely bad idea: the
# provider configuration is inherited in ways that break `destroy`, and by the
# capstone you would be four levels deep.
#
# So the layer became a child module. Now every root composes FLAT:
#
#   module "foundation" { source = ".../module-01-cloud-foundation/foundation" }
#   module "api"        { source = ".../module-02-api-security/foundation/modules/api" }
#   module "tools"      { source = ".../module-05-ai-apis-mcp/foundation/modules/tools" }
#
# One level deep, one provider, and the capstone is just this list with one
# more line on it. That is the whole reason the refactor was worth doing.
#
# Nothing about the resources changed. Same endpoint, same role, same policy.
#
# (c) 2026 Vigilantia Technologies INC. TM HackWithZach.
###############################################################################

# --------------------------------------------------------------------------
# Bedrock runtime endpoint in the foundation's PRIVATE subnets.
# The model is reachable from inside the VPC only. No public path.
#
# This is the one billable hourly resource in the API layer. There are no NAT
# gateways by design. Apply at session start, destroy at session end.
# --------------------------------------------------------------------------
resource "aws_vpc_endpoint" "bedrock_runtime" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [var.endpoint_security_group_id]
  private_dns_enabled = true

  tags = {
    Project = var.project
    Name    = "${var.name_prefix}-bedrock-runtime"
  }
}

# --------------------------------------------------------------------------
# The API's workload role. Least privilege from the start: it may invoke ONE
# model family and read its ONE secret. Nothing else.
#
# Note that this role is hardened even in the baseline profile. That is the
# locked rule of the whole course: the foundation and every proven layer stay
# strong, and only the NEW layer of the current chapter carries a weakness.
# --------------------------------------------------------------------------
data "aws_iam_policy_document" "api_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "api" {
  name               = "${var.name_prefix}-api-role"
  assume_role_policy = data.aws_iam_policy_document.api_assume.json
  tags               = { Project = var.project }
}

# Since 2025, current Claude models on Bedrock are not invoked by their bare
# model id in your own Region. On-demand calls go through a cross-Region
# inference profile (us.<model>), which can route the request to any Region in
# its geography. IAM has to allow BOTH halves: the profile in your Region, and
# the model in every Region the profile can route to. The condition on the
# second statement means the model can only be reached THROUGH that one
# profile, never called directly. Still one model, still no wildcard.
data "aws_caller_identity" "current" {}

locals {
  inference_profile_id  = "${var.inference_geo}.${var.allowed_model}"
  inference_profile_arn = "arn:aws:bedrock:${var.region}:${data.aws_caller_identity.current.account_id}:inference-profile/${local.inference_profile_id}"
}

data "aws_iam_policy_document" "api_perms" {
  statement {
    sid       = "InvokeOneInferenceProfile"
    actions   = ["bedrock:InvokeModel"]
    resources = [local.inference_profile_arn]
  }

  statement {
    sid       = "InvokeOneModelOnlyViaThatProfile"
    actions   = ["bedrock:InvokeModel"]
    resources = [for r in var.inference_regions : "arn:aws:bedrock:${r}::foundation-model/${var.allowed_model}"]

    condition {
      test     = "StringEquals"
      variable = "bedrock:InferenceProfileArn"
      values   = [local.inference_profile_arn]
    }
  }

  statement {
    sid       = "ReadOwnSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.secret_arn]
  }
}

resource "aws_iam_role_policy" "api" {
  name   = "${var.name_prefix}-api-perms"
  role   = aws_iam_role.api.id
  policy = data.aws_iam_policy_document.api_perms.json
}
