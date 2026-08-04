# -----------------------------------------------------------------------------
# AWS WAF for the inference API edge (Module 4, Pillar 1).
#
# The structure firewall that pairs with the guardrail (the meaning firewall).
# Two rules earn their keep immediately:
#   1. AWS managed common rule set  -> command injection, XSS, path traversal,
#      known-bad inputs, bad bots.
#   2. Rate-based rule              -> volumetric floods die at the edge before
#      they ever become tokens and cost (partner to the Ch9 cost cap, LLM10).
#
# Everything is gated on var.waf_enabled so the baseline profile ships nothing
# and the hardened profile brings the whole ACL up with one flag.
# -----------------------------------------------------------------------------

locals {
  on = var.waf_enabled ? 1 : 0
}

resource "aws_wafv2_web_acl" "api" {
  count       = local.on
  name        = "${var.name_prefix}-api-acl"
  description = "Edge firewall for the inference API: managed rules + rate cap."
  scope       = "REGIONAL" # REGIONAL for ALB / API Gateway; CLOUDFRONT otherwise

  default_action {
    allow {}
  }

  # 1. Managed baseline: SQLi, XSS, path traversal, known-bad inputs, bad bots.
  rule {
    name     = "common-rule-set"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-common"
    }
  }

  # 2. Known-bad inputs (command injection payloads, malformed requests).
  rule {
    name     = "known-bad-inputs"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-known-bad"
    }
  }

  # 3. Rate-based rule: the flood dies at the edge.
  rule {
    name     = "rate-limit"
    priority = 3

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-rate"
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-api-acl"
  }
}

# Attach the web ACL to the API's ALB / API Gateway stage, if one was passed.
resource "aws_wafv2_web_acl_association" "api" {
  count        = var.waf_enabled && var.associate_resource_arn != "" ? 1 : 0
  resource_arn = var.associate_resource_arn
  web_acl_arn  = aws_wafv2_web_acl.api[0].arn
}

# Ship WAF logs to CloudWatch so blocked-request events feed the Module 3 SOC.
resource "aws_wafv2_web_acl_logging_configuration" "api" {
  count                   = var.waf_enabled && var.log_group_arn != "" ? 1 : 0
  resource_arn            = aws_wafv2_web_acl.api[0].arn
  log_destination_configs = [var.log_group_arn]
}

output "web_acl_arn" {
  description = "ARN of the API web ACL (empty when WAF disabled)."
  value       = var.waf_enabled ? aws_wafv2_web_acl.api[0].arn : ""
}
