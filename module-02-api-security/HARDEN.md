# The hardening pass, control by control

You attacked the weak API and watched every attack land. Now flip the profile
to hardened and read what each control does. Nothing here is a new file you had
to remember to write. The weak app and the hardened app are the same code; the
weakness was a flag in `app/config.py`, not a missing function.

Run hardened: `HWZ_PROFILE=hardened uvicorn app.main:app`

## 1. Audience-bound token verification

Flag: `verify_audience`

Baseline decodes the token without verifying its signature or its audience, so
any signed token, including one minted for another service, is accepted.
Hardened verifies the signature AND that `aud` equals this API's expected
audience, rejecting a mismatch with 403.

Why it matters: a token is scoped to a purpose. A model API that accepts any
token turns every other token in your system into a key to the model. This is
the confused-deputy shape, and it is the authorization half of LLM06.

## 2. JSON Schema on the body

Flag: `validate_schema`

Baseline accepts any body. Hardened enforces the shape: `prompt` is a string of
bounded length, `max_tokens` is an integer within the per-request ceiling. Out
of bounds is a 400 before the model is ever called.

Why it matters: unbounded input is unbounded cost and unpredictable behavior.
Validation is the cheapest control here and it closes LLM05 and starves the
cost-bomb attack of its oversized payload.

## 3. Per-token rate AND cost cap

Flag: `enforce_caps`

Baseline has no limit. Hardened tracks, per token, request count in a rolling
window and cumulative estimated spend, refusing with 429 (rate) or 402 (cost)
once either ceiling is crossed.

Why it matters: this is the control that shows up on the invoice. LLM10
Unbounded Consumption is the leading reason production AI gets rolled back. A
cap per identity means one abusive caller cannot spend the whole budget or
starve every other user.

## 4. Structured audit logging

Flag: `structured_audit`

Baseline prints an unparseable string with no useful fields. Hardened writes one
JSON line per request with token id, audience, prompt length, tokens, cost, and
outcome.

Why it matters: detection is half the job. The weak log cannot answer "who ran
up this cost" or "was this request served". The structured line can, and it is
the exact input the SIEM in Module 3 forwards and alerts on. No audit, no
detection, no incident response.

## What to check when you are done

Re-run `python3 attack/attack.py --url http://127.0.0.1:8000`. A1 is 403, A2 is
400, A3 trips a 429, and the A4 request appears in the log as a structured line.
Then read each control's effect out loud in one sentence. If you can teach it
back, you own it.

Then stop the app. If you applied the Terraform root, `terraform destroy`.

---

Build it. Release it. Break it. Harden it.

By Zach Marcy. Cybersecurity Architect and Mentor. 20+ years in IT, 6 in cybersecurity. I design and secure cloud environments that deploy and secure APIs and AI.

© 2026 Vigilantia Technologies INC. All rights reserved. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
