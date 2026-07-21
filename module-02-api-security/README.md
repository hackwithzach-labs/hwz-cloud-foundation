# Module 2: API Security (the AI inference API)

Cloud and AI Security Engineer: From Zero to Hired
Build it. Release it. Break it. Harden it.

Pillar 2, part A. The deployment layer between your app and the model. This
module puts an inference API in front of a model and runs the full loop on the
API layer: deploy it insecure, attack it, review the logs, redeploy it
hardened, attack it again, review the logs, tear it down.

## What is weak, and what is not

The module-1 foundation is composed here PINNED HARDENED (see `foundation/main.tf`).
You proved those controls in Chapter 8; they do not get re-weakened. The NEW
layer, the API app, is what starts weak. Its weakness lives in one file,
`app/config.py`, switched by `HWZ_PROFILE`:

| Control | Weak (baseline) | Hardened |
|---|---|---|
| 1. Audience-bound token verification | any signed token accepted | token must be signed AND minted for this API |
| 2. JSON Schema on the body | anything accepted | type + length + bounds enforced |
| 3. Per-token rate AND cost cap | unlimited | rate window + spend ceiling per token |
| 4. Structured audit logging | unparseable string | one JSON line per request |

Each control maps to one attack in `attack/attack.py` and one OWASP LLM Top 10
item: A1->LLM06, A2->LLM05, A3->LLM10, A4 is the detection gap.

## The loop

See `RUNBOOK.md`. Zero-cost warm-up first: `python3 attack/attack.py --selftest`.

## Layout

- `app/` the FastAPI inference API, weak or hardened by `HWZ_PROFILE`.
- `attack/attack.py` the four attacks, with `--selftest` (pure logic, no server).
- `foundation/` the Terraform root: module-1 foundation pinned hardened, plus
  the Bedrock private endpoint and the least-privilege API role.
- `TEACH.md`, `HARDEN.md`, `HOMEWORK.md` the chapter, the control-by-control
  hardening pass, and the week's assignment.

The app fronts a MOCK model call so the whole loop runs locally at zero cost.
The Terraform root is what makes it real in AWS; you do not need it to learn
the loop. Bedrock is on-demand per-token; the only hourly cost in the root is
the interface endpoint, so apply at session start and destroy at session end.

(C) 2026 Vigilantia Technologies INC. All rights reserved. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
