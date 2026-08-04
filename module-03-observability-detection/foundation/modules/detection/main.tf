###############################################################################
# modules/detection :: the SOC layer, weak or wired by ONE flag
#
# Everything here is gated on var.detections_enabled. In the WEAK (blind)
# profile nothing below exists: no alert path, no metric filters, no rules, no
# GuardDuty, no Config, no Security Hub. That is the state hwz-detect proves is
# blind. Flip the flag and the whole SOC comes up on top of the already-hardened
# foundation.
#
# Three detection surfaces, matched to what the foundation actually provides:
#   APP LAYER      CloudWatch metric filters + alarms on the app log group
#   CONTROL PLANE  EventBridge rules on CloudTrail management events
#   BEHAVIORAL     GuardDuty; plus AWS Config (posture/drift) and Security Hub
#
# One alert path (SNS) receives all of them. The student subscribes their own
# email via var.alert_email and confirms it; nothing here hardcodes a recipient.
###############################################################################

locals {
  on = var.detections_enabled ? 1 : 0
}

# --------------------------------------------------------------------------
# ALERT PATH: one SNS topic every detection publishes to.
# --------------------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  count = local.on
  name  = "${var.name_prefix}-alerts"
  tags  = { Project = var.project }
}

# Let CloudWatch alarms and EventBridge publish to the topic.
resource "aws_sns_topic_policy" "alerts" {
  count = local.on
  arn   = aws_sns_topic.alerts[0].arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAndEvents"
      Effect    = "Allow"
      Principal = { Service = ["cloudwatch.amazonaws.com", "events.amazonaws.com"] }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts[0].arn
    }]
  })
}

# The student's email. Empty string -> no subscription -> hwz-detect flags it.
resource "aws_sns_topic_subscription" "email" {
  count     = var.detections_enabled && var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --------------------------------------------------------------------------
# APP LAYER: metric filters on the app log group, each with an alarm.
# The API (Module 2) writes one JSON line per request with a "status" field.
# --------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "unauthorized_access" {
  count          = local.on
  name           = "${var.name_prefix}-unauthorized-access"
  log_group_name = var.app_log_group_name
  pattern        = "{ ($.status = 401) || ($.status = 403) }"

  metric_transformation {
    name          = "UnauthorizedAccess"
    namespace     = "HWZ/AppSecurity"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "cost_cap_breach" {
  count          = local.on
  name           = "${var.name_prefix}-cost-cap-breach"
  log_group_name = var.app_log_group_name
  pattern        = "{ $.status = 429 }"

  metric_transformation {
    name          = "CostCapBreach"
    namespace     = "HWZ/AppSecurity"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_access" {
  count               = local.on
  alarm_name          = "${var.name_prefix}-unauthorized-access"
  namespace           = "HWZ/AppSecurity"
  metric_name         = "UnauthorizedAccess"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_description   = "5+ unauthorized (401/403) responses in a minute. Possible credential stuffing or token abuse."
  alarm_actions       = [aws_sns_topic.alerts[0].arn]
  tags                = { Project = var.project }
}

resource "aws_cloudwatch_metric_alarm" "cost_cap_breach" {
  count               = local.on
  alarm_name          = "${var.name_prefix}-cost-cap-breach"
  namespace           = "HWZ/AppSecurity"
  metric_name         = "CostCapBreach"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_description   = "A 429 cost-cap rejection fired. Someone is pushing on the unbounded-consumption limit (LLM10)."
  alarm_actions       = [aws_sns_topic.alerts[0].arn]
  tags                = { Project = var.project }
}

# --------------------------------------------------------------------------
# CONTROL PLANE: EventBridge rules on CloudTrail management events -> SNS.
# CloudTrail management events reach the default event bus automatically, so
# these need no CloudWatch Logs delivery. Each rule targets the alert topic.
# --------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "cloudtrail_tamper" {
  count       = local.on
  name        = "${var.name_prefix}-cloudtrail-tamper"
  description = "Someone stopping, deleting, or altering the audit trail."
  event_pattern = jsonencode({
    source        = ["aws.cloudtrail"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["cloudtrail.amazonaws.com"]
      eventName   = ["StopLogging", "DeleteTrail", "UpdateTrail"]
    }
  })
  tags = { Project = var.project }
}

resource "aws_cloudwatch_event_rule" "sg_open_to_world" {
  count       = local.on
  name        = "${var.name_prefix}-sg-open-to-world"
  description = "A security group ingress rule being authorized. Inspect for 0.0.0.0/0."
  event_pattern = jsonencode({
    source        = ["aws.ec2"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress"]
    }
  })
  tags = { Project = var.project }
}

resource "aws_cloudwatch_event_rule" "root_account_use" {
  count       = local.on
  name        = "${var.name_prefix}-root-account-use"
  description = "Any API call made by the root account. Root should never be used."
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
    detail = {
      userIdentity = { type = ["Root"] }
    }
  })
  tags = { Project = var.project }
}

resource "aws_cloudwatch_event_target" "cloudtrail_tamper" {
  count = local.on
  rule  = aws_cloudwatch_event_rule.cloudtrail_tamper[0].name
  arn   = aws_sns_topic.alerts[0].arn
}

resource "aws_cloudwatch_event_target" "sg_open_to_world" {
  count = local.on
  rule  = aws_cloudwatch_event_rule.sg_open_to_world[0].name
  arn   = aws_sns_topic.alerts[0].arn
}

resource "aws_cloudwatch_event_target" "root_account_use" {
  count = local.on
  rule  = aws_cloudwatch_event_rule.root_account_use[0].name
  arn   = aws_sns_topic.alerts[0].arn
}

# --------------------------------------------------------------------------
# BEHAVIORAL: GuardDuty. The managed baseline. Reads CloudTrail, VPC flow logs,
# and DNS with no data plumbing on your side.
# --------------------------------------------------------------------------
resource "aws_guardduty_detector" "this" {
  count  = local.on
  enable = true
  tags   = { Project = var.project }
}

# Route GuardDuty findings to the same alert path via EventBridge.
resource "aws_cloudwatch_event_rule" "guardduty_finding" {
  count       = local.on
  name        = "${var.name_prefix}-guardduty-finding"
  description = "Any GuardDuty finding."
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })
  tags = { Project = var.project }
}

resource "aws_cloudwatch_event_target" "guardduty_finding" {
  count = local.on
  rule  = aws_cloudwatch_event_rule.guardduty_finding[0].name
  arn   = aws_sns_topic.alerts[0].arn
}

# --------------------------------------------------------------------------
# POSTURE + DRIFT: AWS Config. Records resource state and evaluates rules.
# Needs its own bucket, a service role, a recorder, and a delivery channel.
# --------------------------------------------------------------------------
resource "aws_s3_bucket" "config" {
  count         = local.on
  bucket        = "${var.name_prefix}-config-${var.account_id}"
  force_destroy = true
  tags          = { Project = var.project }
}

resource "aws_s3_bucket_public_access_block" "config" {
  count                   = local.on
  bucket                  = aws_s3_bucket.config[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "config" {
  count  = local.on
  bucket = aws_s3_bucket.config[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSConfigBucketPermissionsCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource  = aws_s3_bucket.config[0].arn
      },
      {
        Sid       = "AWSConfigBucketDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.config[0].arn}/AWSLogs/${var.account_id}/Config/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}

resource "aws_iam_role" "config" {
  count = local.on
  name  = "${var.name_prefix}-config"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Project = var.project }
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  count      = local.on
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3" {
  count = local.on
  name  = "${var.name_prefix}-config-s3"
  role  = aws_iam_role.config[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetBucketAcl"]
      Resource = [aws_s3_bucket.config[0].arn, "${aws_s3_bucket.config[0].arn}/*"]
    }]
  })
}

resource "aws_config_configuration_recorder" "this" {
  count    = local.on
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config[0].arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "this" {
  count          = local.on
  name           = "${var.name_prefix}-channel"
  s3_bucket_name = aws_s3_bucket.config[0].id
  depends_on     = [aws_config_configuration_recorder.this]
}

resource "aws_config_configuration_recorder_status" "this" {
  count      = local.on
  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.this]
}

# A few managed rules: the compliance cousins of the course scanner.
resource "aws_config_config_rule" "s3_public_read" {
  count = local.on
  name  = "${var.name_prefix}-s3-no-public-read"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder.this]
}

resource "aws_config_config_rule" "root_mfa" {
  count = local.on
  name  = "${var.name_prefix}-root-mfa-enabled"
  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder.this]
}

resource "aws_config_config_rule" "sg_open" {
  count = local.on
  name  = "${var.name_prefix}-restricted-ssh"
  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }
  depends_on = [aws_config_configuration_recorder.this]
}

# --------------------------------------------------------------------------
# ONE VIEW: Security Hub aggregates GuardDuty and Config into a single console.
# --------------------------------------------------------------------------
resource "aws_securityhub_account" "this" {
  count = local.on
}

# --------------------------------------------------------------------------
# A small dashboard so the SOC has a face. Optional to teaching, cheap to keep.
# --------------------------------------------------------------------------
resource "aws_cloudwatch_dashboard" "soc" {
  count          = local.on
  dashboard_name = "${var.name_prefix}-soc"
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric", x = 0, y = 0, width = 12, height = 6
        properties = {
          title  = "Unauthorized (401/403) per minute"
          region = var.region
          view   = "timeSeries"
          metrics = [["HWZ/AppSecurity", "UnauthorizedAccess"]]
        }
      },
      {
        type = "metric", x = 12, y = 0, width = 12, height = 6
        properties = {
          title  = "Cost-cap (429) rejections per minute"
          region = var.region
          view   = "timeSeries"
          metrics = [["HWZ/AppSecurity", "CostCapBreach"]]
        }
      }
    ]
  })
}
