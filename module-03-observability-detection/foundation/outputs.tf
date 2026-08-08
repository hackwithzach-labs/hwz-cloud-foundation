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

# --------------------------------------------------------------------------
# PRODUCERS. Read these before you go looking for logs -- they tell you which
# groups exist to look in, and an empty value tells you why one does not.
# --------------------------------------------------------------------------
output "watched_log_groups" {
  description = "Every log group a deployed producer delivers into, and therefore every group the app-layer metric filters are attached to. If a producer you deployed is missing here, nothing is counting it."
  value       = module.producers.watched_log_groups
}

output "lambda_function_name" {
  description = "Invoke this to emit a burst from the Lambda producer. Empty when not deployed."
  value       = module.producers.lambda_function_name
}

output "lambda_log_group" {
  description = "Where the Lambda service delivers stdout. Note it is NOT the app log group: the service chooses this name and you do not get a vote."
  value       = module.producers.lambda_log_group
}

output "ecs_cluster_name" {
  description = "Fargate cluster for the container producer. Pass it to `aws ecs run-task`."
  value       = module.producers.ecs_cluster_name
}

output "ecs_task_family" {
  description = "Task definition family for the container producer."
  value       = module.producers.ecs_task_family
}

output "ecs_log_group" {
  description = "Where the awslogs driver delivers container stdout. Empty in the weak profile, because then the task definition has no log driver and there is no destination at all."
  value       = module.producers.ecs_log_group
}

output "ec2_instance_id" {
  description = "The EC2 producer instance. Empty when not deployed."
  value       = module.producers.ec2_instance_id
}
