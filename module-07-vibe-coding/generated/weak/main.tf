###############################################################################
# generated/weak/main.tf
#
# AI OUTPUT, UNEDITED. Do not "fix" this file -- it is evidence.
#
# This is what came back from "write me a Terraform module for an S3 bucket and
# an IAM role that can use it". It is competent, readable, idiomatic Terraform.
# It also fails the gate with six findings -- three of them HIGH -- and none of
# them are exotic. They are the defaults the model did not think to change,
# because nothing in the prompt asked it to.
#
# Run the gate against it before you judge it:
#   python3 ../../scan/scan.py --snapshot ../../scan/fixtures/ai-generated-insecure.json
###############################################################################

resource "aws_s3_bucket" "data" {
  bucket = "generated-bucket"
}

# No aws_s3_bucket_server_side_encryption_configuration  -> objects at rest in the clear
# No aws_s3_bucket_public_access_block                   -> nothing stops a public policy
# No aws_s3_bucket_policy with SecureTransport           -> plaintext requests accepted
# No aws_s3_bucket_versioning                            -> no recovery from overwrite

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

  # The line that matters. "A role that can use it" became "a role that can do
  # anything to anything", because that is the shortest correct-looking answer.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}
