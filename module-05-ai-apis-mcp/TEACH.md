# TEACH — Module 5: AI APIs and MCP (Pillar 2)

Start with the end in mind. By the end, the student has given a model tools
through an MCP server, deployed it unlocked, watched it become a confused deputy
holding real credentials — deleting an account, exfiltrating creds via SSRF,
obeying a poisoned tool result — and then locked every door so each abuse dies
somewhere different. This is the code behind **Chapter 12**, and it runs the
locked loop: deploy insecure, scan, attack, harden, scan, attack, review logs.

## The mental model

A model that can call a tool is a confused deputy: it holds legitimate
credentials, it acts on natural language, and (from Chapter 11) that language can
be poisoned. MCP standardizes how the model gets tools, and it collapses three
doors into one place: the **server** (auth/exposure), the **tools' permissions**
(over-scoped), and the **tool descriptions and results** (poisoning = indirect
injection through the tool layer). The fix is one lock per door, never a sterner
prompt.

## > COST SAFETY

The tool-abuse harness (`attack/toolattack.py`) runs against MOCK tools and a
mock MCP — demonstrating `delete_account` or the SSRF fetch costs nothing and
touches nothing real. `scan/scan.py --selftest` and `guard/toolguard.py
--selftest` prove the logic offline with no AWS. Tools deploy as Lambda with no
idle cost; Bedrock stays on-demand per token; tear down at session end.

## The loop (exact commands)

```
terraform apply -var-file=baseline.tfvars     # 1. deploy unlocked
python3 scan/scan.py                           # 2. scan: 5 gaps
python3 attack/toolattack.py                   # 3. attack + review logs: 5/5 succeed
terraform apply -var-file=hardened.tfvars      # 4. harden (or fix.py)
python3 scan/scan.py                           # 5. scan again: PASS
python3 attack/toolattack.py --guarded         # 6. attack + review logs: 0/5
```

See **HARDEN.md** for the control-by-control map and **HOMEWORK.md** for the
week's assignment and the two required log reviews.

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
