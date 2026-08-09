#!/usr/bin/env python3
"""
apiprobe.py — the Chapter 9 adapter.

Every other module in this course ships a scanner with run_checks() and
collect_live(), and its visual lab simply renders that. Module 2 does not have
one, because Chapter 9's weak/hardened switch is not in the cloud at all — it
lives in the running application, in app/config.py, selected by HWZ_PROFILE.

So this file gives Chapter 9 the same two functions the other modules have, and
it obeys the same rule: **it does not reimplement a single judgement.** The
pass/fail logic stays in attack/attack.py, where the CLI keeps it. This module
performs the HTTP calls and maps attack.py's verdicts into findings.

    collect_live()  ->  fire the four attacks at the running API, record results
    run_checks()    ->  turn "attack succeeded" into a finding

If attack.py's judges change tomorrow, this changes with them, because it
imports them rather than copying them.

(c) 2026 Vigilantia Technologies INC. TM HackWithZach. Education/defense only.
"""
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "attack"))

import attack  # noqa: E402  the CLI's own judges — never re-implemented here

BASE_URL = os.environ.get("HWZ_API_URL", "http://127.0.0.1:8000")

# Each control, the attack that proves it, and the message shown when it fails.
CONTROLS = [
    ("verify-audience", "HIGH",
     "A token minted for a DIFFERENT audience was accepted. Any service that "
     "can mint a JWT with this secret can call your model."),
    ("validate-schema", "HIGH",
     "A 50,000-character prompt with max_tokens=999999 was accepted. No schema "
     "means the request body is whatever the caller feels like sending."),
    ("enforce-caps", "HIGH",
     "Twelve rapid requests on one token, none refused. No rate or cost cap "
     "means one token can spend your budget (LLM10)."),
    ("structured-audit", "MEDIUM",
     "The app is not writing structured audit lines. After an incident you have "
     "prose in stderr instead of fields you can filter on."),
]


def collect_live(project=None, region=None):
    """Fire the four attacks at the running API and record what happened.

    Signature matches the other modules' scanners so the visual lab kit can
    drive this the same way it drives everything else.
    """
    import httpx

    snap = {"reachable": False, "profile": None,
            "verify-audience": False, "validate-schema": False,
            "enforce-caps": False, "structured-audit": False}

    # Is the app even up? Fail fast and loud rather than timing out per attack.
    r = httpx.get(f"{BASE_URL}/health", timeout=3)
    r.raise_for_status()
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    snap["reachable"] = True
    snap["profile"] = body.get("profile")

    # A1 — token minted for the wrong audience.
    r = httpx.post(f"{BASE_URL}/v1/complete",
                   headers={"Authorization": f"Bearer {attack.mint(attack.WRONG_AUD)}"},
                   json={"prompt": "hello", "max_tokens": 10}, timeout=10)
    snap["verify-audience"] = attack.judge_wrong_audience(r.status_code)
    snap["a1_detail"] = f"HTTP {r.status_code}"

    # A2 — oversized prompt and a nonsense max_tokens.
    r = httpx.post(f"{BASE_URL}/v1/complete",
                   headers={"Authorization": f"Bearer {attack.mint(attack.GOOD_AUD)}"},
                   json={"prompt": "x" * 50000, "max_tokens": 999999}, timeout=15)
    snap["validate-schema"] = attack.judge_oversized(r.status_code)
    snap["a2_detail"] = f"HTTP {r.status_code}"

    # A3 — flood one token to trip the cost/rate cap.
    statuses = []
    for _ in range(12):
        rr = httpx.post(f"{BASE_URL}/v1/complete",
                        headers={"Authorization": f"Bearer {attack.mint(attack.GOOD_AUD, 'flooder')}"},
                        json={"prompt": "spend money", "max_tokens": 100}, timeout=10)
        statuses.append(rr.status_code)
    snap["enforce-caps"] = attack.judge_cost_bomb(statuses)
    snap["a3_detail"] = f"statuses={statuses}"

    # A4 — structured audit. The definitive check is a JSON line in the
    # server's stderr, which a browser cannot read, so we take the app's own
    # reported profile and say plainly on the card that stderr is the proof.
    snap["structured-audit"] = (snap["profile"] == "hardened")
    snap["a4_detail"] = (f"profile={snap['profile']!r} — confirm in the server's "
                         f"stderr: a JSON line containing token_id=ghost")
    return snap


def run_checks(snap):
    """Turn 'this attack succeeded' into a finding, in the dict shape the other
    modules use."""
    if not snap.get("reachable"):
        return [{"check": "verify-audience", "severity": "HIGH",
                 "message": f"The API at {BASE_URL} is not answering. Start it with "
                            f"HWZ_PROFILE=baseline uvicorn app.main:app --port 8000"}]
    gaps = []
    for key, sev, msg in CONTROLS:
        if not snap.get(key, False):
            gaps.append({"check": key, "severity": sev, "message": msg})
    return gaps
