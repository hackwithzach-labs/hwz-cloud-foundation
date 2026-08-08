# HARDENED profile — every door locked. The MCP server is private and
# authenticated, every tool holds only its own privilege, the model may only
# call registered tools with valid arguments, egress is locked, and the
# tool-call guardrail vets both the call and the result. Re-run scan (PASS) and
# attack/toolattack.py --guarded (0/5), then review the logs.
mcp_authenticated  = true
tool_least_priv    = true
tool_allowlist     = true
egress_locked      = true
toolcall_guardrail = true
