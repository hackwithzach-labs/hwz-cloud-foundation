output "trail_arn" { value = aws_cloudtrail.this.arn }
output "trail_bucket_id" { value = aws_s3_bucket.trail.id }
output "trail_bucket_arn" { value = aws_s3_bucket.trail.arn }
