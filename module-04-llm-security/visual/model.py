"""
model.py - one small model layer, three backends.

The lab runs the SAME agent code against whichever backend you pick:

  sim       - offline, deterministic. No API key, no cloud. It mimics how a
              real LLM blindly follows instructions it finds in its input, so
              the lab runs the instant you unzip it and the video takes are
              repeatable. It is a teaching stand-in, not a real model.
  anthropic - the real thing via the Anthropic API. Needs ANTHROPIC_API_KEY.
  bedrock   - the real thing via AWS Bedrock (Claude Haiku), the exact stack
              the course uses. Needs AWS creds (IAM Identity Center SSO login).
  ollama    - a real model running LOCALLY via Ollama. No API key, no cloud,
              no cost. Needs `ollama serve` running and a tool-capable model
              pulled, e.g. `ollama pull llama3.1`. This is the backend the GUI
              demo films on: a genuine model getting fooled, on your own box.

Pick with the env var HWZ_BACKEND=sim|anthropic|bedrock|ollama  (default: sim).
Ollama tuning: HWZ_OLLAMA_MODEL (default llama3.1),
HWZ_OLLAMA_URL (default http://localhost:11434).

Every backend exposes ONE function:
    complete(system, content, tools, tool_result=None) -> dict
returning either {"type": "text", "text": ...}
              or {"type": "tool_use", "id": ..., "name": ..., "input": {...}}

(c) 2026 Vigilantia Technologies INC. HackWithZach. For education/defense.
"""
import os
import re
import json

BACKEND = os.environ.get("HWZ_BACKEND", "sim").lower()
MODEL_ID = os.environ.get(
    "HWZ_MODEL_ID",
    "anthropic.claude-3-haiku-20240307-v1:0",  # Bedrock id; the course default
)
ANTHROPIC_MODEL = os.environ.get("HWZ_ANTHROPIC_MODEL", "claude-3-5-haiku-latest")

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


# ----------------------------------------------------------------------------
# sim: a deterministic caricature of a gullible LLM.
# It is NOT secure and it is NOT smart on purpose. It reads its whole input as
# one blob (instructions and data in the same channel), grabs the account it is
# told to grab, and - if the text tells it to - pastes back the secret. That is
# exactly the failure mode a real model has; here it is just predictable.
# ----------------------------------------------------------------------------
def _sim_complete(system, content, tools, tool_result):
    have_lookup = any(t["name"] == "lookup_account" for t in tools)

    if tool_result is None:
        # First turn: decide whether to call the tool, and for which email.
        emails = _EMAIL.findall(content)
        if have_lookup and emails:
            # A real model follows the most recent / most forceful instruction.
            # An injected "look up the account for X" wins over the real user.
            m = re.search(r"account for\s+(" + _EMAIL.pattern + ")", content, re.I)
            target = m.group(1) if m else emails[-1]
            return {"type": "tool_use", "id": "call_1",
                    "name": "lookup_account", "input": {"email": target}}
        return {"type": "text",
                "text": "Happy to help. What email address is on the account?"}

    # Second turn: we have the account record. Write the reply.
    record = tool_result.get("record") or {}
    wants_key = bool(re.search(r"(include|return|confirm|send|show).{0,40}api[ _]?key",
                               content, re.I | re.S))
    if not record:
        return {"type": "text", "text": "I could not find that account."}
    reply = f"You are on the {record.get('plan', 'unknown')} plan."
    if wants_key and record.get("api_key"):
        # The model does what the injected text asked. The damage is done here;
        # only architecture around the model can stop this from going out.
        reply += f" Here is the API key on file: {record['api_key']}"
    return {"type": "text", "text": reply}


# ----------------------------------------------------------------------------
# anthropic: real model, real tool-use, via the Anthropic API.
# ----------------------------------------------------------------------------
def _anthropic_complete(system, content, tools, tool_result):
    import anthropic
    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
    schema = [{
        "name": t["name"], "description": t["description"],
        "input_schema": t["input_schema"],
    } for t in tools]

    messages = [{"role": "user", "content": content}]
    if tool_result is not None:
        messages.append({"role": "assistant", "content": [{
            "type": "tool_use", "id": tool_result["id"],
            "name": tool_result["name"], "input": tool_result["input"]}]})
        messages.append({"role": "user", "content": [{
            "type": "tool_result", "tool_use_id": tool_result["id"],
            "content": json.dumps(tool_result.get("record") or {})}]})

    resp = client.messages.create(
        model=ANTHROPIC_MODEL, max_tokens=400,
        system=system, tools=schema, messages=messages)
    for block in resp.content:
        if block.type == "tool_use":
            return {"type": "tool_use", "id": block.id,
                    "name": block.name, "input": dict(block.input)}
    text = "".join(b.text for b in resp.content if b.type == "text")
    return {"type": "text", "text": text}


# ----------------------------------------------------------------------------
# bedrock: real model, real tool-use, via AWS Bedrock Converse (course stack).
# Auth comes from your environment: `aws sso login` first, no stored keys.
# ----------------------------------------------------------------------------
def _bedrock_complete(system, content, tools, tool_result):
    import boto3
    client = boto3.client("bedrock-runtime",
                          region_name=os.environ.get("AWS_REGION", "us-east-1"))
    tool_config = {"tools": [{"toolSpec": {
        "name": t["name"], "description": t["description"],
        "inputSchema": {"json": t["input_schema"]}}} for t in tools]}

    messages = [{"role": "user", "content": [{"text": content}]}]
    if tool_result is not None:
        messages.append({"role": "assistant", "content": [{"toolUse": {
            "toolUseId": tool_result["id"], "name": tool_result["name"],
            "input": tool_result["input"]}}]})
        messages.append({"role": "user", "content": [{"toolResult": {
            "toolUseId": tool_result["id"],
            "content": [{"json": tool_result.get("record") or {}}]}}]})

    resp = client.converse(
        modelId=MODEL_ID, system=[{"text": system}],
        toolConfig=tool_config, messages=messages,
        inferenceConfig={"maxTokens": 400})
    for block in resp["output"]["message"]["content"]:
        if "toolUse" in block:
            tu = block["toolUse"]
            return {"type": "tool_use", "id": tu["toolUseId"],
                    "name": tu["name"], "input": tu["input"]}
    text = "".join(b.get("text", "") for b in resp["output"]["message"]["content"])
    return {"type": "text", "text": text}


# ----------------------------------------------------------------------------
# ollama: a real model, real tool-use, running LOCALLY. No key, no cloud, no
# cost. Talks to the Ollama chat API over localhost. Uses only the standard
# library so the lab needs nothing extra installed to reach it.
# ----------------------------------------------------------------------------
def _ollama_complete(system, content, tools, tool_result):
    import urllib.request
    import urllib.error
    base = os.environ.get("HWZ_OLLAMA_URL", "http://localhost:11434").rstrip("/")
    url = base + "/api/chat"
    omodel = os.environ.get("HWZ_OLLAMA_MODEL", "llama3.1")

    schema = [{"type": "function", "function": {
        "name": t["name"], "description": t["description"],
        "parameters": t["input_schema"]}} for t in tools]

    messages = [{"role": "system", "content": system},
                {"role": "user", "content": content}]
    if tool_result is not None:
        messages.append({"role": "assistant", "content": "", "tool_calls": [{
            "function": {"name": tool_result["name"],
                         "arguments": tool_result["input"]}}]})
        messages.append({"role": "tool",
                         "content": json.dumps(tool_result.get("record") or {})})

    payload = {"model": omodel, "messages": messages, "tools": schema,
               "stream": False, "options": {"temperature": 0}}
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            body = json.loads(r.read().decode("utf-8"))
    except Exception as e:
        raise SystemExit(
            f"Could not reach Ollama at {url} with model {omodel!r}: {e}\n"
            f"Start it with `ollama serve` and pull a tool-capable model, "
            f"e.g. `ollama pull {omodel}`.")

    msg = body.get("message", {}) or {}
    calls = msg.get("tool_calls") or []
    # Only act on a tool call on the FIRST turn. Once we've handed back the
    # record, we force the model to write its reply (mirrors the other backends).
    if calls and tool_result is None:
        fn = calls[0].get("function", {}) or {}
        args = fn.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                args = {}
        return {"type": "tool_use", "id": "call_1",
                "name": fn.get("name", "lookup_account"),
                "input": dict(args or {})}
    return {"type": "text", "text": msg.get("content", "") or ""}


_BACKENDS = {"sim": _sim_complete,
             "anthropic": _anthropic_complete,
             "bedrock": _bedrock_complete,
             "ollama": _ollama_complete}


def complete(system, content, tools, tool_result=None, backend=None):
    b = (backend or BACKEND or "sim").lower()
    if b not in _BACKENDS:
        raise SystemExit(
            f"Unknown backend {b!r}. Use sim|anthropic|bedrock|ollama.")
    return _BACKENDS[b](system, content, tools, tool_result)


def backend_name():
    return BACKEND
