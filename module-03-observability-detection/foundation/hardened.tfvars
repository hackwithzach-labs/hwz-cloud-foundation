###############################################################################
# hardened.tfvars  ::  THE WIRED SOC, FED BY REAL PRODUCERS
#
# Apply with:  terraform apply -var-file=hardened.tfvars
#
# Same code, two flags flipped, and the order they matter in is the lesson.
#
# log_delivery_enabled = true  turns the first half of the chain on. The Lambda
#   gets an explicitly declared log group with retention and KMS instead of the
#   never-expiring unencrypted one the service would have made. The container
#   task definition gains an awslogs driver. The EC2 instance installs the
#   CloudWatch agent, gets a config that maps its file to a group, and gets the
#   IAM permissions to actually write. Three compute types, one JSON contract.
#
# detections_enabled = true    turns the second half on: metric filters attached
#   to EVERY group a producer delivers into, alarms over the aggregated metric,
#   the control-plane EventBridge rules, GuardDuty, Config with rules, Security
#   Hub, and one SNS alert path.
#
# Run a plan against the baseline state and read the diff before you apply. That
# diff IS the SOC. Then apply, emit again, and re-run hwz-detect until it PASSES.
#
# THE ONE THING PEOPLE GET WRONG: a metric filter only evaluates events ingested
# AFTER the filter exists. Anything you emitted while blind is not counted
# retroactively. You must emit again after this apply.
###############################################################################

project     = "hwz"
environment = "lab"
region      = "us-east-1"

# --- the producers layer -----------------------------------------------------
log_delivery_enabled = true
log_retention_days   = 7

lambda_producer    = true  # no idle cost
container_producer = true  # no idle cost
ec2_producer       = false # flip to true to watch the CloudWatch agent work.
# ~$0.01/hr. Destroy at session end.

# --- the detection layer -----------------------------------------------------
detections_enabled = true

# SET THIS to your own email. AWS emails you a confirmation link; click it before
# you run the attack, or alerts publish to an unconfirmed address and you see
# nothing. hwz-detect flags an unconfirmed alert path as a HIGH gap.
alert_email = "you@example.com"
