output "alert_topic_arn" {
  description = "SNS topic the SOC publishes to. Empty in the blind profile."
  value       = module.detection.alert_topic_arn
}

output "guardduty_detector_id" {
  description = "GuardDuty detector id. Empty in the blind profile."
  value       = module.detection.guardduty_detector_id
}

output "app_log_group" {
  description = "The foundation app log group the metric filters watch."
  value       = module.foundation.app_log_group
}

output "cloudtrail_bucket" {
  description = "The CloudTrail S3 bucket you query with Athena for history."
  value       = module.foundation.cloudtrail_bucket
}
