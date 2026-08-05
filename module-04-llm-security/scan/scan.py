#!/usr/bin/env python3
"""
scan.py  -  hwz-scan, the LLM-security posture check for Module 4.

Same shape as hwz-scan (Ch8) and hwz-detect (Ch10): reading the posture is
split from judging it, so the logic is testable with no cloud at all.

  collect_live()  turns the deployed stack into a plain posture snapshot
                  (does the API have an input guardrail, an output filter, a
                  data/instruction boundary, a WAF web ACL, a rate rule).
  run_checks()    judges the snapshot and returns the gaps.

Naked profile  -> 5 gaps. Hardened profile -> 0. One flag pair flips it:
guardrails_enabled and waf_enabled.

    python3 scan/scan.py --project hwz --region us-east-1     # live account
    python3 scan/scan.py --selftest                          # offline proof

(c) 2026 Vigilantia Technologies INC. HackWithZach. Education/defense only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Each check: key, severity, and the one-line "why this is a hole" message.
CHECKS = [
    ("guardrail-input", "HIGH",
     "No input guardrail. Injection reaches the model unfiltered (LLM01)."),
    ("guardrail-output", "HIGH",
     "No output filter. A leaked secret or system prompt ships as-is (LLM02)."),
    ("channel-boundary", "HIGH",
     "Untrusted content shares the instruction channel (indirect injection, LLM01)."),
    ("waf-web-acl", "MEDIUM",
     "No WAF on the API edge. Floods, scanners, cmd-injection and XSS reach the origin."),
    ("waf-rate-rule", "MEDIUM",
     "No rate-based rule. Volumetric abuse becomes tokens and cost (LLM10)."),
]

# Map each check key to the snapshot field that, when True, means it is wired.
SNAPSHOT_KEY = {
    "guardrail-input": "input_guardrail",
    "guardrail-output": "output_guardrail",
    "channel-boundary": "instruction_data_boundary",
    "waf-web-acl": "waf_web_acl",
    "waf-rate-rule": "waf_rate_rule",
}


def run_checks(snapshot: dict) -> list[dict]:
    """Pure: given a posture snapshot, return the list of gaps."""
    gaps = []
    for key, sev, msg in CHECKS:
        if not snapshot.get(SNAPSHOT_KEY[key], False):
            gaps.append({"check": key, "severity": sev, "message": msg})
    return gaps


def collect_live(project: str, region: str) -> dict:
    """Read the real posture. In the lab this reads the deployed config the
    Terraform emits (a small JSON the module writes on apply); in a real
    account you would extend this to describe the WAF web ACL and the API's
    guardrail wiring via boto3. Falls back to the naked posture if absent."""
    path = os.environ.get("HWZ_LLM_POSTURE",
                          os.path.join(os.path.dirname(__file__), "posture.json"))
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    # No posture file => nothing is wired => the naked account.
    return {k: False for k in SNAPSHOT_KEY.values()}


# ---------------------------------------------------------------------------
# LAB CONSOLE MAP  (added) — ties this CLI run to its card in the HWZ Lab
# Console, so terminal output and the dashboard are provably the same story.
#   findings (rc=1) -> the red card;   clean (rc=0) -> the green card.
# ---------------------------------------------------------------------------
_CONSOLE_CARD = 'Prompt Injection'
_CONSOLE_META = 'Chapter 11 · Pillar 1: LLM'
_CONSOLE_WEAK = 'LEAKED'
_CONSOLE_HARD = 'BLOCKED'
_CONSOLE_UNIT = 'guardrail/WAF gap(s)'
_CONSOLE_WLINE = 'with these open, indirect injection leaks the secret'
_CONSOLE_HLINE = 'guardrail + WAF wired, both directions'


def console_map(rc, n):
    rule = "  " + "─" * 62
    print()
    print(rule)
    print("  LAB CONSOLE MAP  —  what you just saw, on the chart")
    print(rule)
    print(f"  Card   : {_CONSOLE_CARD}   ({_CONSOLE_META})")
    if rc == 0:
        print(f'  State  : HARDENED  · green   Console verdict: "{_CONSOLE_HARD}"')
        print(f"  Match  : {_CONSOLE_HLINE} — exactly what the green card shows.")
    else:
        print(f'  State  : WEAK      · red     Console verdict: "{_CONSOLE_WEAK}"')
        print(f"  Match  : {n} {_CONSOLE_UNIT} — {_CONSOLE_WLINE},")
        print("           which is what the red card shows.")
    print(f'  Chart  : flip the "{_CONSOLE_CARD}" card in the Lab Console for the same result.')
    print(rule)


def report(*a, **k):
    rc = _report(*a, **k)
    try:
        n = len(a[-1])
    except Exception:
        n = rc
    console_map(rc, n)
    return rc


def _report(gaps: list[dict]) -> int:
    if not gaps:
        print("PASS. Guardrail and WAF are wired. "
              "Injection is filtered, floods die at the edge.")
        return 0
    print(f"NAKED. {len(gaps)} gap(s):\n")
    for g in gaps:
        print(f"  [{g['severity']:<6}] {g['check']:<17} {g['message']}")
    return 1


# ---------------------------------------------------------------------------
# SELF-TEST
# ---------------------------------------------------------------------------
BLIND_FIXTURE = {
    "input_guardrail": False, "output_guardrail": False,
    "instruction_data_boundary": False, "waf_web_acl": False,
    "waf_rate_rule": False,
}
WIRED_FIXTURE = {
    "input_guardrail": True, "output_guardrail": True,
    "instruction_data_boundary": True, "waf_web_acl": True,
    "waf_rate_rule": True,
}


def selftest() -> int:
    blind = run_checks(BLIND_FIXTURE)
    wired = run_checks(WIRED_FIXTURE)
    print(f"selftest: blind fixture -> {len(blind)} gaps (expected 5)")
    print(f"selftest: wired fixture -> {len(wired)} gaps (expected 0)")
    ok = len(blind) == 5 and len(wired) == 0
    print("selftest: PASS" if ok else "selftest: FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="hwz-scan: LLM-security posture check.")
    ap.add_argument("--project", default="hwz")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return report(run_checks(collect_live(args.project, args.region)))


if __name__ == "__main__":
    sys.exit(main())
