###############################################################################
# baseline.tfvars  ::  THE BLIND ACCOUNT  (no detection, nothing shipping)
#
# Apply with:  terraform apply -var-file=baseline.tfvars
#
# The foundation underneath is fully hardened (you proved it in Chapter 8). Two
# things are weak here, and they are weak independently, because in real
# accounts they fail independently.
#
# 1. DELIVERY is off. The producers deploy and run: a Lambda that writes to
#    stdout, a container task that writes to stdout, and (if you turn it on) an
#    EC2 instance whose application appends structured audit lines to a file
#    every minute. None of it reaches CloudWatch. The Lambda group is whatever
#    the service decides to make, the task definition has no log driver, and the
#    instance has no agent and no role. The evidence is being generated right
#    now and it is dying where it is written.
#
# 2. DETECTION is off. No alert path, no metric filters, no EventBridge rules,
#    no GuardDuty, no Config, no Security Hub.
#
# This is what most accounts look like the day after go-live. Run hwz-detect,
# watch it fail across the board, then go read the boxes and see that the
# evidence was there the whole time and nothing told you.
###############################################################################

project     = "hwz"
environment = "lab"
region      = "us-east-1"

# --- the producers layer -----------------------------------------------------
# The compute exists; the shipping does not.
log_delivery_enabled = false

lambda_producer    = true  # no idle cost
container_producer = true  # no idle cost
ec2_producer       = false # ~$0.01/hr while it runs -- opt in, then destroy

# --- the detection layer -----------------------------------------------------
detections_enabled = false
# alert_email is irrelevant while blind: nothing is publishing anywhere.
