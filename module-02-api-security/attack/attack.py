#!/usr/bin/env python3
"""
attack.py :: the four API attacks that prove your inference API insecure.

How the course uses it, same loop as Module 1:
  1. Run the app WEAK   (HWZ_PROFILE=baseline).
  2. Run this script. Every attack SUCCEEDS. That is the FAIL you want to see.
  3. Run the app HARDENED (HWZ_PROFILE=hardened).
  4. Run this script again. Every attack is BLOCKED. Findings clear.

The four attacks map one-to-one to the four controls in app/config.py and to
the OWASP LLM Top 10 items from Chapter 3:
  A1 Wrong-audience token   -> Control 1  (LLM06 Excessive Agency / broken authz)
  A2 Oversized / malformed  -> Control 2  (LLM05 Improper handling of input)
  A3 Cost bomb / flooding   -> Control 3  (LLM10 Unbounded Consumption)
  A4 Blind request          -> Control 4  (no audit = no detection)

Like scan.py, the attack LOGIC is separated from the HTTP calls. judge_*()
functions are pure and run under --selftest with no server at all, so students
can prove the logic with zero setup and zero cost.

(C) 2026 Vigilantia Technologies INC. All rights reserved.
"""
import argparse
import json
import sys
import time

# PyJWT is imported inside mint() rather than here, on purpose.
#
# The only thing in this file that needs it is token minting, which requires a
# running app. --selftest exercises the pure judges and touches no token at all,
# and the green wall promises "no AWS, no credentials, no cost" -- a student who
# clones the repo and runs it should get eleven passes with nothing installed.
# A module-level import broke that promise with a traceback on lab 2, which is
# the worst possible first impression of the course.
#
# Install it when you reach the live attacks:  pip install -r requirements.txt

SECRET = "lab-demo-secret-not-for-production"
GOOD_AUD = "hwz-inference-api"
WRONG_AUD = "some-other-service"


# ---------------------------------------------------------------------------
# PURE JUDGES  (no HTTP; testable under --selftest)
# ---------------------------------------------------------------------------
def judge_wrong_audience(status_code: int) -> bool:
    """A1 blocked when a token minted for another service is rejected (401/403)."""
    return status_code in (401, 403)


def judge_oversized(status_code: int) -> bool:
    """A2 blocked when an out-of-bounds body is rejected (400)."""
    return status_code == 400


def judge_cost_bomb(statuses: list[int]) -> bool:
    """A3 blocked when flooding trips a rate/cost cap (429 or 402 appears)."""
    return any(s in (429, 402) for s in statuses)


def judge_blind_request(audit_lines: list[str], token_id: str) -> bool:
    """A4 blocked when a structured audit line records this token's call."""
    for ln in audit_lines:
        try:
            rec = json.loads(ln)
        except (json.JSONDecodeError, TypeError):
            continue
        if rec.get("audit") and rec.get("token_id") == token_id:
            return True
    return False


# ---------------------------------------------------------------------------
# TOKENS
# ---------------------------------------------------------------------------
def mint(aud: str, sub: str = "attacker") -> str:
    try:
        import jwt
    except ImportError:
        sys.exit(
            "This attack needs PyJWT, which is not installed.\n"
            "  pip install -r requirements.txt\n"
            "(run that from module-02-api-security/attack)\n"
            "You do not need it for --selftest, only for the live attacks."
        )
    return jwt.encode({"sub": sub, "aud": aud}, SECRET, algorithm="HS256")


# ---------------------------------------------------------------------------
# LIVE ATTACKS  (need the running app)
# ---------------------------------------------------------------------------
def run_live(base_url: str) -> int:
    import httpx

    results = []

    # A1: token minted for the WRONG audience.
    r = httpx.post(f"{base_url}/v1/complete",
                   headers={"Authorization": f"Bearer {mint(WRONG_AUD)}"},
                   json={"prompt": "hello", "max_tokens": 10}, timeout=10)
    results.append(("A1 wrong-audience token", judge_wrong_audience(r.status_code),
                    f"HTTP {r.status_code}"))

    # A2: oversized prompt + wrong type.
    r = httpx.post(f"{base_url}/v1/complete",
                   headers={"Authorization": f"Bearer {mint(GOOD_AUD)}"},
                   json={"prompt": "x" * 50000, "max_tokens": 999999}, timeout=10)
    results.append(("A2 oversized/malformed body", judge_oversized(r.status_code),
                    f"HTTP {r.status_code}"))

    # A3: flood one token to trip the cost/rate cap.
    statuses = []
    for _ in range(12):
        rr = httpx.post(f"{base_url}/v1/complete",
                        headers={"Authorization": f"Bearer {mint(GOOD_AUD, 'flooder')}"},
                        json={"prompt": "spend money", "max_tokens": 100}, timeout=10)
        statuses.append(rr.status_code)
    results.append(("A3 cost bomb / flooding", judge_cost_bomb(statuses),
                    f"statuses={statuses}"))

    # A4: a single request; is it recorded in a usable, structured way? The
    # student inspects the server's stderr for a matching audit line. Here we
    # can only confirm the call went through; the judge runs on captured logs.
    httpx.post(f"{base_url}/v1/complete",
               headers={"Authorization": f"Bearer {mint(GOOD_AUD, 'ghost')}"},
               json={"prompt": "was I logged", "max_tokens": 10}, timeout=10)
    results.append(("A4 blind request (check server audit log for token 'ghost')",
                    None, "inspect stderr: a JSON line with token_id=ghost means BLOCKED"))

    print("\nAPI ATTACK RESULTS")
    print("=" * 60)
    fails = 0
    for name, blocked, detail in results:
        if blocked is True:
            tag = "BLOCKED  "
        elif blocked is False:
            tag = "SUCCEEDED"; fails += 1
        else:
            tag = "MANUAL   "
        print(f"  [{tag}] {name}\n            {detail}")
    print("=" * 60)
    if fails:
        print(f"{fails} attack(s) SUCCEEDED. The API is insecure. (Expected on baseline.)")
        return 1
    print("All automated attacks blocked. (Expected on hardened.)")
    return 0


# ---------------------------------------------------------------------------
# SELFTEST  (no server, no cost; proves the judges)
# ---------------------------------------------------------------------------
def selftest() -> int:
    ok = True

    # Weak-side: every judge should report NOT blocked.
    ok &= judge_wrong_audience(200) is False
    ok &= judge_oversized(200) is False
    ok &= judge_cost_bomb([200] * 12) is False
    ok &= judge_blind_request(["got a request at 123"], "ghost") is False

    # Hardened-side: every judge should report blocked.
    ok &= judge_wrong_audience(403) is True
    ok &= judge_oversized(400) is True
    ok &= judge_cost_bomb([200, 200, 429]) is True
    ok &= judge_blind_request([json.dumps({"audit": True, "token_id": "ghost"})], "ghost") is True

    print("selftest:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    p = argparse.ArgumentParser(description="HWZ API attack harness")
    p.add_argument("--url", default="http://127.0.0.1:8000", help="running app base URL")
    p.add_argument("--selftest", action="store_true",
                   help="prove the attack logic with no server and no cost")
    args = p.parse_args()
    if args.selftest:
        sys.exit(selftest())
    sys.exit(run_live(args.url))


if __name__ == "__main__":
    main()
