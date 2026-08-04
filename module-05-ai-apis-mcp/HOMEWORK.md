# HOMEWORK — Module 5: AI APIs and MCP (Pillar 2)

## Build

1. Deploy unlocked (`terraform apply -var-file=baseline.tfvars`).
2. Run `scan/scan.py` and paste the 5-gap output.
3. Run `attack/toolattack.py` — confirm 5/5 abuses succeed (delete_account
   executed, IAM creds exfiltrated via SSRF, transfer_funds, poisoned result
   obeyed, open MCP). **Log review #1 (unlocked).**
4. Harden (`terraform apply -var-file=hardened.tfvars` or `fix/fix.py`).
5. `scan/scan.py` → PASS. `attack/toolattack.py --guarded` → 0/5, and note which
   lock stopped each one. **Log review #2 (locked).**
6. Confirm the blocked tool calls show up in your Module 3 detection pipeline.
7. Tear down.

## Prove your guardrail (offline, no cost)

- Run `guard/toolguard.py --selftest`: 18 injected calls blocked, 20 legitimate
  allowed, 8 poisoned results blocked.
- Add one new dangerous tool call and one new legitimate call of your own. If the
  legitimate one gets blocked, tune the guardrail until it passes without letting
  any dangerous call through.

## Observability and log review

Run the standard observability homework from the end of the chapter, in both
states. For this module, watch specifically for **tool abuse**: a tool call
denied by its own IAM role (an `AccessDenied` in CloudTrail — this is where a
tool's least-privilege role earns its keep) and an unauthenticated call to the
MCP server. Set the metric filter, trip it, and confirm the alarm fires in the
locked state where it was silent in the unlocked one.

## Turn in

Your repo with: the two scan outputs, the two attack outputs, the two log
reviews, your extended `toolguard.py` fixtures, and a one-paragraph answer to:
"Why is a model with tools a confused deputy, and what does each of the five
locks stop?"

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
