###############################################################################
# baseline.tfvars  ::  THE NAKED AGENT  (insecure ON PURPOSE)
#
# Apply with:  terraform apply -var-file=baseline.tfvars
#
# Every loop control is off. This is an autonomous agent with a mutable goal,
# unguarded memory, one broad role, no step cap, no human gate, and no audit.
# It DEPLOYS CLEAN — it is not broken, it is wide open. Scan it, run the abuse
# harness, understand every hole, then harden.
###############################################################################

project     = "hwz"
environment = "lab"
region      = "us-east-1"

goal_locked      = false   # goal can be hijacked mid-run
memory_guardrail = false   # poisoned notes persist and fire later
tool_least_priv  = false   # one broad role for the whole loop
step_budget      = false   # loop can run away
hitl_approval    = false   # irreversible actions fire autonomously
run_audit        = false   # autonomous abuse is invisible after the fact
