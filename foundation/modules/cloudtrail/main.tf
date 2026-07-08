###############################################################################
# modules/cloudtrail
# The account trail AND its log bucket, together, so the bucket policy is always
# correct. This is the module the old course got wrong: bad bucket ARN, missing
# CloudTrail service statements, and no depends_on, so the trail tried to create
# before the bucket would accept its writes.
#
# The trail always deploys. Whether it is USEFUL is controlled by flags:
#   baseline  -> single region, no log validation, no data events, no KMS
#   hardened  -> multi region, log validation, S3 data events, KMS encryption
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

# The CORRECT CloudTrail bucket policy. Two statements, exact ARNs.
resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
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
