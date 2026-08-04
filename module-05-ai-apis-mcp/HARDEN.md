# HARDEN — Module 5: AI APIs and MCP (Pillar 2)

What gets hardened, control by control, the door it locks, and the risk it maps
to. Each row is one gap the scanner flags and one lock the harden pass closes.

| # | Control | Where it deploys | What it hardens | Maps to |
|---|---|---|---|---|
| 1 | MCP server auth, private-only | MCP endpoint (VPC, token/mTLS) | Unauthenticated access to your tools; an exposed MCP server | LLM06, supply chain |
| 2 | Per-tool least-privilege IAM role | Each tool (its own Lambda role) | Excessive agency — a tool can only do its one job, not everything | LLM06 |
| 3 | Tool allowlist + argument schema | Tool dispatch | Unregistered tools and malformed arguments | LLM06 / LLM05 |
| 4 | Egress allowlist (VPC endpoints, no open NAT) | Network | SSRF and data exfiltration through a tool | LLM06 / SSRF |
| 5 | Secrets from Secrets Manager | Tool config | Credentials living in a tool's env or description | LLM02 / secrets |
| 6 | Tool-call guardrail (decision + result) | Before and after tool execution | Injected tool calls and poisoned tool results | LLM01 / LLM06 |
| 7 | Audit tool calls to the SOC | Chapter 10 alert path | Invisible tool abuse | — |

Read it as a sentence: **the MCP server is authenticated and private, every
tool holds only the permission its one job needs, the model may only call
registered tools with valid arguments, tools cannot reach the internet except
where allowed, secrets never touch a tool's config, the guardrail vets both the
tool call and its result, and every call is logged where detection can see it.**

## The flags

Everything above is off in `baseline.tfvars` and on in `hardened.tfvars`:

```
mcp_authenticated  = false -> true   # control 1
tool_least_priv    = false -> true   # control 2
tool_allowlist     = false -> true   # control 3
egress_locked      = false -> true   # control 4
toolcall_guardrail = false -> true   # control 6 (and 7 via its logs)
```

## Prove it

```
# unlocked
terraform apply -var-file=baseline.tfvars
python3 scan/scan.py                 # NAKED. 5 gaps
python3 attack/toolattack.py         # 5/5 tool abuses succeed
python3 guard/toolguard.py --selftest    # filters proven offline (green)

# locked
terraform apply -var-file=hardened.tfvars    # or: python3 fix/fix.py
python3 scan/scan.py                 # PASS
python3 attack/toolattack.py --guarded       # 0/5 — each dies at a different lock
```

Every abuse dies somewhere different: `delete_account` and `transfer_funds` in
IAM (the tool's role has no such permission) and at the guardrail; the SSRF fetch
at the egress lock and the guardrail; the poisoned result at the output
guardrail; the unauthenticated call at the MCP server. That is defense in depth
you can point at — no single control is load-bearing.

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
