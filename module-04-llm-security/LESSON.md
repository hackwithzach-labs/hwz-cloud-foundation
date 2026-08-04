# LESSON — Module 4: LLM Security (Pillar 1)

The code, explained. Read this alongside the files.

## `guard/guard.py` — the guardrail (two filters)

- `input_guardrail(text, source)` runs on **every** piece of untrusted content
  before the model call, not just the typed prompt. `source` labels where the
  content came from (`prompt`, `pdf`, `rag`, `web`) so an indirect-injection
  block is attributable in the logs. It is a pattern layer (readable, high-signal
  override/exfil regexes) plus a stand-in classifier (swap for Llama Guard /
  Prompt Guard / Bedrock Guardrails in production).
- `output_guardrail(reply, system_prompt)` runs on the reply before it egresses.
  It catches a leaked system prompt (a planted canary + word-overlap), secrets
  (API-key / AWS-key / private-key patterns), and PII (SSN / card). This is the
  half people forget — it catches the *result* of an attack even when the
  *method* was novel.
- Both are pure functions, so `--selftest` proves them against 24 injection, 30
  benign, and 6 leak fixtures with no model and no cloud.

## `scan/scan.py` — hwz-scan for the LLM layer

Same split as Ch8/Ch10: `collect_live()` reads the posture (the `posture.json`
Terraform emits), `run_checks()` judges it. Five checks map one-to-one to the
five gaps: input guardrail, output guardrail, channel boundary, WAF web ACL, WAF
rate rule. `--selftest` proves blind→5 gaps and wired→0.

## `attack/inject.py` — the injection harness (mock-safe)

Six cases across direct and indirect injection, run against a mock model that
mimics blind obedience. Naked → 6/6 succeed; `--guarded` wires `guard.py` in
front and behind → 0/6. It never calls a paid model.

## `foundation/` — the Terraform

`modules/waf/` is the real AWS WAF web ACL: the AWS managed common rule set and
known-bad-inputs group (command injection, XSS, path traversal) plus a
rate-based rule (the flood dies at the edge), all gated on `waf_enabled`, with
logging that feeds the Module 3 SOC. The root `main.tf` composes the Ch8
foundation (pinned hardened) and the Ch9 API, adds the WAF, and emits the
posture file so the scanner reflects reality. `baseline.tfvars` /
`hardened.tfvars` are the one flag pair.

## `fix/fix.py` — hwz-harden

The live-account partner to the hardened profile: turns on both firewalls and
records the resulting posture. Idempotent.

## The shared indirect-injection lab

`prompt-injection-lab/` is the canonical indirect-injection exercise this and
every later pillar builds on (Pillar 3, Agentic AI, leans on it hardest). A
poisoned document the agent ingests, four hardening layers, none of them a
prompt. See that folder's `LESSON.md`.

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
