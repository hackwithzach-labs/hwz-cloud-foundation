"""
main.py :: the AI inference API, weak or hardened by one env flag.

POST /v1/complete takes a prompt and returns a (mock) model completion. The
four AI-API controls from Chapter 9 each guard this endpoint and are toggled by
config.py. The model call is mocked so the whole loop runs locally at zero cost.

An ALWAYS-ON safety breaker (config.ABS_*) sits under all of it and cannot be
disabled by any profile. It protects your real bill, because AWS billing alerts
but does not hard-stop. See config.py for the full rationale.

(C) 2026 Vigilantia Technologies INC. All rights reserved.
"""
import json
import sys
import time
from collections import defaultdict

import jwt
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from app import config

C = config.load()
app = FastAPI(title="HWZ Inference API", version="2.0")

_usage = defaultdict(lambda: {"count": 0, "cost": 0.0, "window_start": time.time()})
_WINDOW_SECONDS = 60

# Process-wide model-call counter for the absolute safety breaker. NOT the
# teaching cap (that one is per-token and profile-gated). This is unconditional.
_model_calls = {"n": 0}


def safety_breaker(requested_tokens: int) -> int:
    """Always-on. No profile disables it. Protects the real bill, not the lesson.
    Returns the clamped token count."""
    if _model_calls["n"] >= config.ABS_MAX_MODEL_CALLS_PER_PROCESS:
        raise HTTPException(
            status_code=503,
            detail="Absolute safety breaker: process model-call limit reached. "
                   "Restart the app to continue. This protects your bill; it is "
                   "not the teaching cap.")
    return min(requested_tokens, config.ABS_MAX_TOKENS_PER_CALL)


# Control 1: audience-bound token verification
def authenticate(authorization):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1]
    if C.verify_audience:
        try:
            claims = jwt.decode(token, config.JWT_SECRET, algorithms=["HS256"],
                                audience=config.EXPECTED_AUDIENCE)
        except jwt.InvalidAudienceError:
            raise HTTPException(status_code=403, detail="Token audience mismatch")
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid token")
    else:
        claims = jwt.decode(token, options={"verify_signature": False})
    return claims


# Control 2: JSON Schema on the request body
def validate_body(body):
    if not C.validate_schema:
        return
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Body must be an object")
    prompt = body.get("prompt")
    if not isinstance(prompt, str):
        raise HTTPException(status_code=400, detail="prompt must be a string")
    if not (1 <= len(prompt) <= 2000):
        raise HTTPException(status_code=400, detail="prompt length out of bounds")
    max_tokens = body.get("max_tokens", 100)
    if not isinstance(max_tokens, int) or not (1 <= max_tokens <= config.MAX_TOKENS_PER_REQUEST):
        raise HTTPException(status_code=400, detail="max_tokens out of bounds")


# Control 3: per-token rate AND cost cap (the TEACHING cap)
def enforce_caps(token_id, est_cost):
    if not C.enforce_caps:
        return
    u = _usage[token_id]
    now = time.time()
    if now - u["window_start"] > _WINDOW_SECONDS:
        u["count"] = 0
        u["window_start"] = now
    if u["count"] + 1 > config.MAX_REQUESTS_PER_TOKEN:
        raise HTTPException(status_code=429, detail="Rate cap exceeded")
    if u["cost"] + est_cost > config.MAX_COST_PER_TOKEN_USD:
        raise HTTPException(status_code=402, detail="Cost cap exceeded")
    u["count"] += 1
    u["cost"] += est_cost


# Control 4: structured audit logging
def audit(event):
    if C.structured_audit:
        print(json.dumps({"audit": True, **event}), file=sys.stderr, flush=True)
    else:
        print(f"got a request at {time.time()}", file=sys.stderr, flush=True)


def mock_model_complete(prompt, max_tokens):
    out_tokens = min(max_tokens, 50)
    total_tokens = len(prompt.split()) + out_tokens
    cost = total_tokens * 0.00002
    return (f"[mock completion for {prompt[:40]!r}]", total_tokens, cost)


@app.post("/v1/complete")
async def complete(request: Request, authorization: str | None = Header(default=None)):
    claims = authenticate(authorization)
    token_id = claims.get("sub", "unknown")

    raw = await request.body()
    try:
        body = json.loads(raw or b"{}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Body is not valid JSON")

    validate_body(body)
    prompt = body.get("prompt", "")
    max_tokens = body.get("max_tokens", 100)

    est_cost = (len(str(prompt).split()) + 50) * 0.00002
    enforce_caps(token_id, est_cost)

    # Teaching cap (Control 3) may be off in baseline. The safety breaker is NOT:
    # it runs before every model call, in every profile, and clamps token count
    # so a real bill can never run away in this lab.
    req_tokens = int(max_tokens) if isinstance(max_tokens, int) else 100
    req_tokens = safety_breaker(req_tokens)
    _model_calls["n"] += 1

    completion, used_tokens, cost = mock_model_complete(str(prompt), req_tokens)
    audit({"token_id": token_id, "audience": claims.get("aud"),
           "prompt_len": len(str(prompt)), "tokens": used_tokens,
           "cost_usd": round(cost, 5), "outcome": "ok"})
    return JSONResponse({"completion": completion, "tokens": used_tokens, "cost_usd": round(cost, 5)})


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "profile": "hardened" if C.enforce_caps else "baseline",
            "safety_breaker": "always-on"}
