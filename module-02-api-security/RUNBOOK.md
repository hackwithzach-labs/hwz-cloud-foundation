# Runbook: the loop on the API layer

Same four-step loop as Module 1, now on the inference API. Use an ISOLATED
SANDBOX AWS account for the Terraform part. The app + attack loop runs locally
at zero cost, so do that first to learn the moves.

## 0. Provision the API and watch it work (build BEFORE you break)

Set up the environment, stand up the MINIMAL API (no security), and send it a
real request. You secure what you understand, so meet the pipeline first.

```bash
cd module-02-api-security
python3 -m venv .venv && source .venv/bin/activate
pip install -r app/requirements.txt

uvicorn app.minimal:app --port 8000      # terminal 1: the irreducible API, no controls
```

In a second terminal, send it a request and watch a completion come back:

```bash
curl -s localhost:8000/v1/complete -H "Content-Type: application/json" \
  -d '{"prompt": "hello there how are you", "max_tokens": 20}'
# -> {"completion":"[mock completion for 'hello there how are you']","tokens":25,"cost_usd":0.0005}
```

Read `app/minimal.py` top to bottom (about 20 lines). The numbered comments are
the eight hops a request travels. Four of them, who-is-calling, is-input-sane,
has-this-caller-had-enough, and did-I-record-it, ask no question at all. Those
four open hops are the four controls you add next. Stop the minimal server
(Ctrl+C) when you have seen it work.

## 0b. Zero-cost warm-up: prove the attack logic (no server)

```bash
python3 attack/attack.py --selftest      # proves the attack logic. Expect PASS.
```

## 1. Build and release the WEAK API

```bash
HWZ_PROFILE=baseline uvicorn app.main:app --port 8000
```

Leave it running. In a second terminal:

## 2. Break it (attacks SUCCEED on purpose)

```bash
python3 attack/attack.py --url http://127.0.0.1:8000
```

Expect A1, A2, A3 to SUCCEED and a non-zero exit. A wrong-audience token is
accepted, a 50k-char body is accepted, and a flood never trips a cap.

## 3. Review the logs, WEAK

Look at the API's stderr. The only record is `got a request at <time>`: no
token id, no cost, no outcome. For attack A4, search for the ghost token:

```bash
# nothing structured to find. That absence is the lesson.
```

## 4. Redeploy HARDENED and break it again

Stop the app, restart hardened, re-run the same attacks:

```bash
HWZ_PROFILE=hardened uvicorn app.main:app --port 8000
python3 attack/attack.py --url http://127.0.0.1:8000    # expect all BLOCKED, exit 0
```

A1 -> 403, A2 -> 400, A3 -> 429 once the cap trips.

## 5. Review the logs, HARDENED

The same stderr now emits one JSON line per request. Confirm A4: the ghost
request is recorded with its token id, cost, and outcome.

```bash
# a line like: {"audit": true, "token_id": "ghost", ... "outcome": "ok"}
```

## 6. The real thing in AWS (optional, low-cost, teardown when done)

```bash
cd foundation
terraform init
terraform apply -auto-approve       # foundation hardened + Bedrock endpoint + API role
# ... point the app at the Bedrock endpoint, run the loop against a real model ...
terraform destroy -auto-approve     # remove the one hourly resource (the endpoint)
```

The foundation deploys hardened here because you proved it in Chapter 8. Only
the app layer runs the weak-then-hardened loop.

COST SAFETY for the real step: run the app HARDENED only against a real model
(HWZ_PROFILE=hardened HWZ_USE_REAL_MODEL=true), pinned to the cheapest model
with a tiny max_tokens. Do NOT run the flooding attack (A3) against a real
model. The always-on breaker in app/config.py caps the process at 25 calls and
clamps token size as a backstop, but the rule stands: the flood is a mock-only
demonstration. Budgets alert, they do not hard-stop, so the code is your real
guardrail. Destroy the moment you are done.
