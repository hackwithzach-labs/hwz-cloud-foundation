###############################################################################
# modules/s3
# The general-purpose data bucket. Every weakness here is a flag, not a missing
# resource, so the bucket always deploys. Baseline: public-capable, unencrypted,
# unversioned, plaintext allowed. Hardened: block public access, default KMS
# encryption, versioning, and a bucket policy that denies non-TLS requests.
###############################################################################

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "this" {
  bucket = "${var.name_prefix}-data-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = var.versioning ? "Enabled" : "Suspended"
  }
}

# Block Public Access. Only attached when hardened.
resource "aws_s3_bucket_public_access_block" "this" {
  count                   = var.block_public_access ? 1 : 0
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Default encryption. Only attached when hardened. Uses the foundation KMS key.
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  count  = var.default_encryption ? 1 : 0
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

# TLS-only bucket policy. Only attached when hardened. Denies any request that
# is not over HTTPS.
resource "aws_s3_bucket_policy" "tls" {
  count  = var.enforce_tls ? 1 : 0
  bucket = aws_s3_bucket.this.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.this.arn,
        "${aws_s3_bucket.this.arn}/*"
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.this]
}
