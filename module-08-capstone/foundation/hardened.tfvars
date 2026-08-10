# hardened.tfvars — all four pillars, plus the SOC.
#
# Same stack, same payload, different outcome. Run the identical attack after
# applying this and watch it die at the first lock it meets.
guardrail_enabled       = true
goal_lock_enabled       = true
tool_least_priv_enabled = true
hitl_approval_enabled   = true
run_audit_enabled       = true
