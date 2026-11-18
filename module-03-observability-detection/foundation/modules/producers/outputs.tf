###############################################################################
# modules/producers :: outputs.tf
#
# These are the handles the detection layer and the runbook consume. The
# watched_log_groups output is the important one: it is the answer to "which
# groups must the metric filters be attached to", and getting that list wrong is
# the failure this whole module exists to teach.
###############################################################################

output "lambda_function_name" {
  description = "The Lambda producer. Invoke it to emit a burst. Empty when not deployed."
  value       = var.lambda_producer ? aws_lambda_function.emitter[0].function_name : ""
}

output "lambda_log_group" {
  description = "Where the Lambda service delivers this function's stdout. Note that it is NOT the app log group -- that is the point."
  value       = var.lambda_producer ? local.lambda_log_group : ""
}

output "ecs_cluster_name" {
  description = "Fargate cluster for the container producer. Empty when not deployed."
  value       = var.container_producer ? aws_ecs_cluster.this[0].name : ""
}

output "ecs_task_family" {
  description = "Task definition family to pass to `aws ecs run-task`."
  value       = var.container_producer ? aws_ecs_task_definition.producer[0].family : ""
}

output "ecs_log_group" {
  description = "Where the awslogs driver delivers container stdout. Empty when log delivery is off, because then there is no destination at all."
  value       = var.container_producer && var.log_delivery_enabled ? local.ecs_log_group : ""
}

output "ec2_instance_id" {
  description = "The EC2 producer. Empty when not deployed."
  value       = var.ec2_producer ? aws_instance.producer[0].id : ""
}

output "watched_log_groups" {
  description = "Every group a producer actually delivers into, in this configuration. The detection layer attaches the app-layer metric filters to each one. If a producer is deployed but its group is missing from this list, the filters cannot see it -- which is exactly the failure hwz-detect reports."
  # The names come from the log group RESOURCES, not from the locals, on
  # purpose. A metric filter can only be put on a log group that already
  # exists. Reading the name off the resource gives Terraform an implicit
  # dependency, so every filter in module.detection waits for its group to be
  # created. Reading the same string off a local gives no dependency at all,
  # and the apply races: PutMetricFilter -> ResourceNotFoundException.
  #
  # The Lambda group falls back to the local only when delivery is off, because
  # then this lab deliberately does not declare it (the Lambda service creates
  # it on first invoke). The names are plain config values, so they are known
  # at plan time and stay valid for_each keys downstream.
  value = compact([
    var.app_log_group_name,
    var.lambda_producer ? try(aws_cloudwatch_log_group.lambda[0].name, local.lambda_log_group) : "",
    var.container_producer && var.log_delivery_enabled ? aws_cloudwatch_log_group.ecs[0].name : "",
  ])
}

output "log_delivery_enabled" {
  description = "Echoes the weak/hardened state of this layer so the root module and the runbook agree on which story is being told."
  value       = var.log_delivery_enabled
}
