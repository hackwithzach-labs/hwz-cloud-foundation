# LESSON — Module 5: AI APIs and MCP (Pillar 2)

The code, explained.

## `guard/toolguard.py` — the tool-call guardrail

Two pure functions. `input_guardrail(tool, args)` runs on the model's decision
before the tool executes: it blocks dangerous tools (`delete_account`,
`transfer_funds`, …), unregistered tools (anything not on the allowlist), SSRF
targets in the arguments (`169.254.169.254`, RFC1918, `file://`, localhost), and
injected instructions in the arguments. `output_guardrail(result)` runs on the
tool's return value before the model sees it: a poisoned result carrying an
instruction, a secret, or PII is blocked, because a poisoned result is indirect
injection wearing a tool's uniform. `--selftest` proves both against 18 injected
calls, 20 legitimate calls, and 8 poisoned results.

## `scan/scan.py` — hwz-scan for the tool layer

Same split as every scanner: `collect_live()` reads the posture (the
`posture.json` the Terraform emits), `run_checks()` judges it. Five checks map to
the five gaps: MCP auth, per-tool least privilege, tool-call guardrail, tool
allowlist, egress lock. `--selftest` proves unlocked→5 and locked→0.

## `attack/toolattack.py` — the tool-abuse harness (mock-safe)

Five abuses against a mock MCP and mock tools: excessive agency, SSRF egress,
tool poisoning, poisoned result, open MCP. Unlocked → 5/5. `--guarded` wires the
guardrail in front of and behind each call and requires MCP auth → 0/5, each
dying at a different lock.

## `foundation/` — the Terraform

`modules/tools/` is the control that matters most: when `tool_least_priv` is on,
each tool gets its OWN scoped role (`lookup_account` reads one table;
`send_email` calls SES only); when off, every tool shares one broad role with
`dynamodb:*`, `ses:*`, `s3:*`, `secretsmanager:*` — the weak default the scanner
flags. The root `main.tf` composes the Ch8 foundation and Ch9 API pinned
hardened, adds the tools, and emits the posture file. `baseline.tfvars` /
`hardened.tfvars` are the one flag set.

## `fix/fix.py` — hwz-harden

The live-account partner: locks the MCP + tool layer and records the posture.
Idempotent.

## Where it plugs in

Pillar 3 (Agentic AI) chains these tool calls in a loop toward a goal, so every
weakness here compounds. The shared indirect-injection lab from Chapter 11
delivers its payload through a poisoned tool result here. Every blocked call logs
into the Chapter 10 SOC.

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
