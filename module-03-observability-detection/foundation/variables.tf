variable "project" {
  description = "Project tag / name prefix that scopes the lab. hwz-detect reads the same value."
  type        = string
  default     = "hwz"
}

variable "environment" {
  description = "Environment suffix, e.g. lab."
  type        = string
  default     = "lab"
}

variable "region" {
  description = "Region the lab runs in."
  type        = string
  default     = "us-east-1"
}

variable "detections_enabled" {
  description = "The weak/hardened switch for the detection layer. Set by the tfvars files: false in baseline, true in hardened."
  type        = bool
  default     = false
}

variable "alert_email" {
  description = "YOUR email. AWS sends a confirmation link you must click before any alert is delivered. Set it in hardened.tfvars or with -var. Left empty, the SOC deploys but has no confirmed alert path and hwz-detect flags it."
  type        = string
  default     = ""
}

###############################################################################
# PRODUCERS LAYER  --  who writes the log
#
# Detection is arithmetic on a stream. These variables control whether there is
# a stream at all, and whether it reaches CloudWatch.
###############################################################################

variable "log_delivery_enabled" {
  description = "The weak/hardened switch for the PRODUCERS layer, set by the tfvars files. false = compute runs and its output never reaches CloudWatch. true = every deployed producer delivers. Deliberately separate from detections_enabled so you can build the most instructive failure in the module: a perfect SOC watching log groups nothing writes to."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "Retention on every log group this lab declares. The number matters less than the fact that one exists: a log group you never declared is created for you with retention Never Expire, and you pay to store debug output until someone notices."
  type        = number
  default     = 7
}

variable "lambda_producer" {
  description = "Deploy the Lambda producer. No idle cost -- it bills per invocation, and lab-scale invocations are free tier. On by default."
  type        = bool
  default     = true
}

variable "container_producer" {
  description = "Deploy the ECS Fargate producer. No idle cost -- the cluster and task definition are free and a task bills per second only while you run it. On by default."
  type        = bool
  default     = true
}

variable "ec2_producer" {
  description = "Deploy the EC2 producer. THE ONLY PRODUCER WITH AN IDLE HOURLY CHARGE: a t3.micro runs about $0.01/hr, roughly $0.25 for a day you forget to destroy. OFF by default so nobody gets a surprise. Turn it on to watch the CloudWatch agent work, then destroy at session end."
  type        = bool
  default     = false
}

variable "instance_type" {
  description = "Instance type for the EC2 producer. t3.micro is plenty to tail a file."
  type        = string
  default     = "t3.micro"
}
