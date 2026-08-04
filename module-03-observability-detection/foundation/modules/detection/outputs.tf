output "alert_topic_arn" {
  description = "The SNS topic every detection publishes to (empty in the blind profile)."
  value       = var.detections_enabled ? aws_sns_topic.alerts[0].arn : ""
}

output "guardduty_detector_id" {
  description = "The GuardDuty detector id (empty in the blind profile)."
  value       = var.detections_enabled ? aws_guardduty_detector.this[0].id : ""
}

output "config_bucket" {
  description = "The AWS Config delivery bucket (empty in the blind profile)."
  value       = var.detections_enabled ? aws_s3_bucket.config[0].id : ""
}
