###############################################################################
# modules/producers :: variables.tf
#
# The producers layer answers a question Chapter 10 used to skip: WHO WRITES THE
# LOG. A metric filter is arithmetic on a stream that already exists. If nothing
# is delivering, the most beautiful detection chain in the world counts zero.
#
# Three producers, because AWS has exactly three shapes of answer:
#   lambda    -- the service captures stdout for you, into ITS OWN log group
#   ec2       -- nothing is automatic; an agent + an IAM role or the logs die
#   container -- the task definition's log driver decides, or output goes nowhere
###############################################################################

variable "name_prefix" {
  description = "Name prefix, e.g. hwz-lab. Everything this module creates carries it."
  type        = string
}

variable "project" {
  description = "Project tag. hwz-detect scopes its reads by this string."
  type        = string
}

variable "region" {
  description = "Region the lab runs in."
  type        = string
}

variable "app_log_group_name" {
  description = "The foundation app log group. The EC2 CloudWatch agent ships into this one."
  type        = string
}

variable "vpc_id" {
  description = "Foundation VPC id."
  type        = string
}

variable "public_subnet_ids" {
  description = "Foundation public subnets. EC2 and Fargate sit here ON PURPOSE: a public subnet with an egress-only security group reaches CloudWatch over the internet gateway, which is free. The private-subnet answer is interface VPC endpoints, which bill roughly $0.01/hr per endpoint per AZ. The chapter teaches the endpoint pattern; the lab does not charge you for it."
  type        = list(string)
}

variable "kms_key_arn" {
  description = "Foundation customer-managed key. Log groups created here are encrypted with it in the hardened profile."
  type        = string
}

# --------------------------------------------------------------------------
# THE WEAK / HARDENED SWITCH FOR THIS LAYER
# --------------------------------------------------------------------------
variable "log_delivery_enabled" {
  description = "false = the compute runs and produces output that never reaches CloudWatch (no agent on EC2, no log driver on the container, no declared group for Lambda). true = every producer delivers. This is the weak/hardened flip for the producers layer and it is deliberately SEPARATE from detections_enabled, so you can stand in the most instructive failure in the whole module: filters and alarms perfectly configured, watching a log group nothing writes to."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "Retention on every log group this module declares. The point is that a number exists at all: an undeclared Lambda group defaults to Never Expire, and you pay for that forever."
  type        = number
  default     = 7
}

# --------------------------------------------------------------------------
# PER-PRODUCER TOGGLES  (cost lives here, so it is one line to read)
# --------------------------------------------------------------------------
variable "lambda_producer" {
  description = "Deploy the Lambda producer. Free at lab scale and has no idle cost -- it bills per invocation only. Default on."
  type        = bool
  default     = true
}

variable "container_producer" {
  description = "Deploy the ECS Fargate producer. Zero idle cost: the cluster and task definition are free, and a task bills per second only while you run it (a 30s run is a fraction of a cent). Default on."
  type        = bool
  default     = true
}

variable "ec2_producer" {
  description = "Deploy the EC2 producer. THIS IS THE ONLY PRODUCER WITH AN IDLE HOURLY CHARGE -- a t3.micro is roughly $0.01/hr, about $0.25 for a day you forget to destroy. Default OFF so nobody gets surprised; flip it to true when you want to watch the CloudWatch agent do its job, and destroy at session end."
  type        = bool
  default     = false
}

variable "instance_type" {
  description = "EC2 instance type for the agent demo. t3.micro is enough to tail a file."
  type        = string
  default     = "t3.micro"
}
