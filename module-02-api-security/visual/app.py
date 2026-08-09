#!/usr/bin/env python3
"""
Chapter 9 — API Security Foundations, as a visual lab.

Four controls as cards, proved by firing the four attacks at your RUNNING API
and reading attack.py's own verdicts. The weak/hardened switch for this chapter
is not in AWS — it is HWZ_PROFILE in the app process — so this lab needs no
credentials and no deployed infrastructure. It needs the app running.

    # terminal 1
    $env:HWZ_PROFILE="baseline"
    python -m uvicorn app.main:app --port 8000

    # terminal 2
    pip install flask httpx pyjwt
    python app.py                 # http://localhost:5109

Flip HWZ_PROFILE to hardened, restart the API, refresh this page, and watch
every card go green without a single line of code changing.

(c) 2026 Vigilantia Technologies INC. TM HackWithZach.
"""
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_DIR))

import apiprobe as scanner        # noqa: E402  calls attack.py's judges
from hwzvisual import VisualLab   # noqa: E402

# The API is not running in the sample states, so the samples are pure posture.
WEAK = {"reachable": True, "profile": "baseline", "verify-audience": False,
        "validate-schema": False, "enforce-caps": False, "structured-audit": False}
HARD = {"reachable": True, "profile": "hardened", "verify-audience": True,
        "validate-schema": True, "enforce-caps": True, "structured-audit": True}

CARDS = [
    {"key": "verify-audience", "name": "Audience-Bound Tokens", "chain": "who is calling",
     "why": "A JWT is only proof if you check who it was issued for. Without an audience check, any service holding the signing secret can call your model as anyone."},
    {"key": "validate-schema", "name": "Request Schema", "chain": "what they may send",
     "why": "A JSON Schema on every body. Without it the request is whatever the caller feels like sending &mdash; 50,000 characters, a max_tokens of 999999, a string where a number belongs."},
    {"key": "enforce-caps", "name": "Rate and Cost Caps", "chain": "how much they may spend",
     "why": "Per-token rate and cost limits. This is the control between a compromised key and a five-figure bill, and it is the one people add after the invoice arrives."},
    {"key": "structured-audit", "name": "Structured Audit Log", "chain": "what you can prove after",
     "why": "One JSON line per request with fields you can filter on. This is what Chapter 10's metric filters count &mdash; prose in stderr is not evidence."},
]

lab = VisualLab(
    scanner=scanner,
    chapter=9,
    pillar="Pillar: Cloud",
    title="API Security &mdash; weak vs hardened profile",
    subtitle="Four controls, one environment variable. The model is not your attack surface; the API in front of it is.",
    cards=CARDS,
    weak_word="BREACHED",
    hard_word="BLOCKED",
    weak_line="Attacks are landing. The API leaks and over-serves.",
    hard_line="Every automated attack blocked. Same code, same cloud, one environment variable.",
    cli_hint="python attack/attack.py --url http://localhost:8000",
    chain_footer="This chapter's weakness is not in AWS. <b>It is four flags in app/config.py</b> &mdash; which is where most real API breaches live.",
    demo_snapshots={"weak": WEAK, "hardened": HARD},
    needs_aws=False,
)

app = lab.flask_app()

if __name__ == "__main__":
    lab.run()
