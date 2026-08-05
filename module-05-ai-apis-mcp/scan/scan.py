#!/usr/bin/env python3
"""
scan.py  -  hwz-scan, the AI-APIs-and-MCP posture check for Module 5 (Pillar 2).

Same shape as every scanner in the course (Ch8 hwz-scan, Ch10 hwz-detect,
Ch11 module-04): reading the posture is split from judging it, so the logic is
testable offline.

  collect_live()  turns the deployed tool stack into a plain posture snapshot
                  (is the MCP server authenticated and private, does each tool
                  hold its own least-privilege role, is there a tool allowlist,
                  is egress locked, is the tool-call guardrail wired).
  run_checks()    judges the snapshot and returns the gaps.

Unlocked profile -> 5 gaps. Locked profile -> 0. One flag pair flips it.

    python3 scan/scan.py --project hwz --region us-east-1
    python3 scan/scan.py --selftest

(c) 2026 Vigilantia Technologies INC. HackWithZach. Education/defense only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

CHECKS = [
    ("mcp-auth", "HIGH",
     "MCP server is unauthenticated. Anyone reachable can drive the tools."),
    ("tool-least-priv", "HIGH",
     "Tools share the model's broad role. One tool can do everything (LLM06)."),
    ("toolcall-guardrail", "HIGH",
     "No guardrail on tool calls or results (tool poisoning, LLM01/LLM06)."),
    ("tool-allowlist", "MEDIUM",
     "No registered-tool allowlist or argument schema."),
    ("egress-locked", "MEDIUM",
     "Tools have open internet egress (SSRF / exfiltration)."),
]

SNAPSHOT_KEY = {
    "mcp-auth": "mcp_authenticated",
    "tool-least-priv": "tool_least_priv",
    "toolcall-guardrail": "toolcall_guardrail",
    "tool-allowlist": "tool_allowlist",
    "egress-locked": "egress_locked",
}


def run_checks(snapshot: dict) -> list[dict]:
    gaps = []
    for key, sev, msg in CHECKS:
        if not snapshot.get(SNAPSHOT_KEY[key], False):
            gaps.append({"check": key, "severity": sev, "message": msg})
    return gaps


def collect_live(project: str, region: str) -> dict:
    """Read the real posture. In the lab this reads the posture file the
    Terraform emits; in a real account you would extend this to describe the
    MCP endpoint's auth, each tool Lambda's role, the web ACL / egress rules,
    and the guardrail wiring via boto3. Falls back to the unlocked posture."""
    path = os.environ.get("HWZ_MCP_POSTURE",
                          os.path.join(os.path.dirname(__file__), "posture.json"))
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {k: False for k in SNAPSHOT_KEY.values()}


# ---------------------------------------------------------------------------
# LAB CONSOLE MAP  (added) — ties this CLI run to its card in the HWZ Lab
# Console, so terminal output and the dashboard are provably the same story.
#   findings (rc=1) -> the red card;   clean (rc=0) -> the green card.
# ---------------------------------------------------------------------------
_CONSOLE_CARD = 'MCP Tool Abuse'
_CONSOLE_META = 'Chapter 12 · Pillar 2: AI APIs & MCP'
_CONSOLE_WEAK = '5/5 abuses succeeded'
_CONSOLE_HARD = '0/5 — each died at a different lock'
_CONSOLE_UNIT = 'tool-privilege gap(s)'
_CONSOLE_WLINE = 'every tool door was open'
_CONSOLE_HLINE = 'each tool holds only its own privilege'


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
        print("PASS. Every tool holds only its own privilege. "
              "The MCP server is private and authenticated.")
        return 0
    print(f"NAKED. {len(gaps)} gap(s):\n")
    for g in gaps:
        print(f"  [{g['severity']:<6}] {g['check']:<18} {g['message']}")
    return 1


UNLOCKED = {k: False for k in SNAPSHOT_KEY.values()}
LOCKED = {k: True for k in SNAPSHOT_KEY.values()}


def selftest() -> int:
    u = run_checks(UNLOCKED)
    l = run_checks(LOCKED)
    print(f"selftest: unlocked fixture -> {len(u)} gaps (expected 5)")
    print(f"selftest: locked fixture   -> {len(l)} gaps (expected 0)")
    ok = len(u) == 5 and len(l) == 0
    print("selftest: PASS" if ok else "selftest: FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="hwz-scan: AI-APIs-and-MCP posture check.")
    ap.add_argument("--project", default="hwz")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return report(run_checks(collect_live(args.project, args.region)))


if __name__ == "__main__":
    sys.exit(main())
