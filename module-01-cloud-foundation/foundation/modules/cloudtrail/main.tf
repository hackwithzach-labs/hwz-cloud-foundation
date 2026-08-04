###############################################################################
# modules/cloudtrail
# The account trail AND its log bucket, together, so the bucket policy is always
# correct. This is the module the old course got wrong: bad bucket ARN, missing
# CloudTrail service statements, and no depends_on, so the trail tried to create
# before the bucket would accept its writes.
#
# The trail always deploys. Whether it is USEFUL is controlled by flags:
#   baseline  -> single region, no log validation, no data events, no KMS,
#                plaintext requests allowed to the log bucket, no versioning
#   hardened  -> multi region, log validation, S3 data events, KMS encryption,
#                TLS-only log bucket, versioned log bucket
#
# The log bucket is your evidence store. In hardened it gets the SAME two
# protections as the data bucket -- deny-non-TLS and versioning -- so a
# tampered or replayed request can't reach it in the clear and a delete can't
# erase the trail objects. The scanner checks the trail bucket exactly like any
# other bucket, so these two flags are what clear its MEDIUM (TLS) and LOW
# (versioning) findings.
###############################################################################

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "trail" {
  bucket        = "${var.name_prefix}-cloudtrail-${random_id.suffix.hex}"
  force_destroy = true # lab convenience so terraform destroy is clean
}

# The trail log bucket is never public, in baseline or hardened. That is not the
# lesson we are teaching with this stack, so we do it right unconditionally.
resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Versioning on the evidence store. Suspended in baseline, Enabled in hardened.
resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = var.versioning ? "Enabled" : "Suspended"
  }
}

locals {
  # The CORRECT CloudTrail bucket policy. Two statements, exact ARNs. Always on.
  trail_base_statements = [
    {
      Sid       = "AWSCloudTrailAclCheck"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "s3:GetBucketAcl"
      Resource  = aws_s3_bucket.trail.arn
    },
    {
      Sid       = "AWSCloudTrailWrite"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${var.account_id}/*"
      Condition = {
        StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
      }
    }
  ]

  # Hardened only: deny any request to the log bucket that is not over TLS.
  # Same concat-with-empty pattern as the KMS module so Terraform never has to
  # unify two differently-shaped statement lists.
  trail_tls_statement = {
    Sid       = "DenyInsecureTransport"
    Effect    = "Deny"
    Principal = "*"
    Action    = "s3:*"
    Resource = [
      aws_s3_bucket.trail.arn,
      "${aws_s3_bucket.trail.arn}/*"
    ]
    Condition = {
      Bool = { "aws:SecureTransport" = "false" }
    }
  }

  trail_statements = concat(
    local.trail_base_statements,
    var.enforce_tls ? [local.trail_tls_statement] : [],
  )
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = local.trail_statements
  })
}

resource "aws_cloudtrail" "this" {
  name                          = "${var.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = var.multi_region
  enable_log_file_validation    = var.log_file_validation
  include_global_service_events = true
  kms_key_id                    = var.use_kms && var.kms_key_arn != "" ? var.kms_key_arn : null

  dynamic "event_selector" {
    for_each = var.data_events ? [1] : []
    content {
      read_write_type           = "All"
      include_management_events = true

      data_resource {
        type   = "AWS::S3::Object"
        values = ["arn:aws:s3"]
      }
    }
  }

  # Without this, the trail can be created before the bucket policy exists and
  # AWS rejects it with "incorrect S3 bucket policy". This one line is the fix.
  depends_on = [aws_s3_bucket_policy.trail]
}
