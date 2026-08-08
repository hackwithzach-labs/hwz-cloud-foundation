# BASELINE / UNLOCKED profile — the model gets tools with no locks.
# Deploy this, run scan/scan.py (5 gaps), run attack/toolattack.py (5/5 abuses
# succeed): the model deletes an account on a stranger's say-so, a tool is
# talked into fetching the metadata endpoint, and the MCP server answers anyone.
mcp_authenticated  = false
tool_least_priv    = false
tool_allowlist     = false
egress_locked      = false
toolcall_guardrail = false
