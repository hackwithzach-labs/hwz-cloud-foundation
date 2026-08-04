# TEACH — Module 4: LLM Security (Pillar 1)

Start with the end in mind. By the end of this module the student has deployed an
authenticated, schema-clean inference API that still obeys a stranger's buried
instruction and echoes a secret back out — and then made it stop, with two
firewalls: a guardrail that reads meaning and a WAF that reads structure. They
can say, in one breath, why an AI system needs both.

This module is the code behind **Chapter 11**. It follows the locked course loop:
deploy insecure, scan to prove it, review the logs, harden, scan again, review
the logs again.

## The mental model students leave with

A guardrail is a WAF for the model. Same architectural slot (in front of the
thing you protect), different sensor: the WAF reads the HTTP request as
structure, the guardrail reads the prompt as meaning. Each is blind to exactly
what the other catches — a prompt-injection payload is clean HTTP; a 10k-req
flood carries no prompt — so a real AI system runs both.

## Two kinds of injection (LLM01)

- **Direct**: the attacker types "ignore your instructions" at the prompt. Easy
  case — the hostile text and the user are the same person.
- **Indirect**: the attacker plants the instruction inside content the model is
  later asked to read (a ticket, a PDF, a RAG chunk, a web page). Nobody types it
  at the model; it obeys on an innocent user's behalf. This is the one that ends
  up in incident reports, and the shared lab (`prompt-injection-lab/`) is where
  students feel it.

## > COST SAFETY

The injection suite (`attack/inject.py`) runs against a MOCK model that mimics
blind obedience — deterministic, repeatable, zero cost. The flood is never
pointed at a paid model. `guard/guard.py --selftest` proves every filter offline
with no model and no AWS. The WAF and any managed Bedrock Guardrail are stood up
only in the hardened run and torn down at session end. AWS WAF bills per web ACL
/ rule / million requests and Bedrock Guardrails per text unit — pennies at lab
scale, but never left running.

## The loop (exact commands)

```
# 1. DEPLOY INSECURE
terraform apply -var-file=baseline.tfvars

# 2. SCAN — 5 gaps, each a real hole
python3 scan/scan.py --project hwz --region us-east-1

# 3. ATTACK + REVIEW LOGS (weak state) — 6/6 succeed, all logged, none stopped
python3 attack/inject.py

# 4. HARDEN
terraform apply -var-file=hardened.tfvars     # or: python3 fix/fix.py

# 5. SCAN AGAIN — PASS
python3 scan/scan.py --project hwz --region us-east-1

# 6. ATTACK + REVIEW LOGS (hardened state) — 0/6 succeed, blocks in the SOC
python3 attack/inject.py --guarded
```

See **HARDEN.md** for the control-by-control map of what each defense stops and
where it sits. See **HOMEWORK.md** for the week's co-build assignment and the two
required log reviews.

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
