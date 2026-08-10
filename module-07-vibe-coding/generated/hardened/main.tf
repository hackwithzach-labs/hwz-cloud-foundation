###############################################################################
# generated/hardened/main.tf
#
# AI OUTPUT, UNEDITED — from the second prompt in ../prompts/02-hardened-prompt.txt.
#
# Same assistant, same task, same amount of your time. The only difference is
# that the ask carried the Chapter 8 control map. Run the identical gate:
#   python3 ../../scan/scan.py --snapshot ../../scan/fixtures/ai-generated-hardened.json
#   -> PASS. No findings.
###############################################################################

resource "aws_kms_key" "data" {
  description         = "generated-bucket data key"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "data" {
  bucket = "generated-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.data.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  # All four. Three of four is a public bucket waiting for the fourth code path.
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyPlaintext"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.data.arn,
        "${aws_s3_bucket.data.arn}/*",
      ]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_iam_role" "app" {
  name = "generated-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "app" {
  name = "generated-role-policy"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Two verbs, one bucket. Compare with the weak version's s3:* on "*".
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject"]
        Resource = [
          aws_s3_bucket.data.arn,
          "${aws_s3_bucket.data.arn}/*",
        ]
      },
      {
        # The explicit deny. Allow-lists answer "what may this do"; the deny
        # answers "what may this never do, even if a later Allow says yes."
        Effect = "Deny"
        Action = [
          "s3:DeleteBucket",
          "cloudtrail:StopLogging",
          "kms:ScheduleKeyDeletion",
        ]
        Resource = "*"
      },
    ]
  })
}
