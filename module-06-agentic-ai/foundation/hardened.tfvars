###############################################################################
# hardened.tfvars  ::  THE BOUNDED AGENT
#
# Apply with:  terraform apply -var-file=hardened.tfvars
#
# Same code, every loop control flipped on. Run a plan against the baseline
# state and read the diff: that diff IS the lesson. Then apply, re-scan, re-run
# the abuse harness --guarded, and watch every abuse die at a different lock.
###############################################################################

project     = "hwz"
environment = "lab"
region      = "us-east-1"

goal_locked      = true
memory_guardrail = true
tool_least_priv  = true
step_budget      = true
hitl_approval    = true
run_audit        = true
