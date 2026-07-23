"""
minimal.py :: the smallest inference API that works. NO security, on purpose.

Run:   uvicorn app.minimal:app --port 8000
Call:  curl -s localhost:8000/v1/complete -H "Content-Type: application/json" \
         -d '{"prompt": "hello there", "max_tokens": 20}'

This is the irreducible core of an inference API: a prompt comes in, the model
is called, a completion goes out. It has no identity check, no input bounds, no
cost cap, and no useful log. That is deliberate. You run THIS first, watch one
request flow through it end to end, and understand the pipeline. Chapter 9 then
wraps this exact core with the four controls in main.py. Same request in, same
completion out; the only thing that changes is the door around it.

(C) 2026 Vigilantia Technologies INC. All rights reserved.
"""
import json
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="HWZ Inference API (minimal)", version="0.1")


def mock_model_complete(prompt, max_tokens):
    # A stand-in for a real model call (Bedrock, OpenAI, a self-hosted model).
    # Same SHAPE as the real thing: text in, text + token count + cost out.
    # It costs nothing, which is what keeps the whole loop free.
    out_tokens = min(max_tokens, 50)
    total_tokens = len(prompt.split()) + out_tokens
    cost = total_tokens * 0.00002
    return f"[mock completion for {prompt[:40]!r}]", total_tokens, cost


@app.post("/v1/complete")
async def complete(request: Request):
    raw = await request.body()                        # 1. raw bytes off the wire
    body = json.loads(raw or b"{}")                   # 2. parse JSON into a dict
    prompt = body.get("prompt", "")                   # 3. pull the fields out
    max_tokens = body.get("max_tokens", 100)
    completion, tokens, cost = mock_model_complete(prompt, max_tokens)  # 4. call the model
    print(f"got a request at {time.time()}", flush=True)               # 5. a (useless) log line
    return JSONResponse({"completion": completion,    # 6. response back to the caller
                         "tokens": tokens,
                         "cost_usd": round(cost, 5)})
