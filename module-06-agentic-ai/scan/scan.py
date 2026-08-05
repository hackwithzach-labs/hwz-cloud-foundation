#!/usr/bin/env python3
"""
scan.py  -  hwz-scan, the Agentic-AI posture check for Module 6 (Pillar 3).

Same shape as every scanner in the course (Ch8 hwz-scan, Ch10 hwz-detect,
Ch11 module-04, Ch12 module-05): reading the posture is split from judging it,
so the logic is testable offline with no AWS.

Pillar 2 secured a SINGLE tool call. Pillar 3 secures a LOOP: an agent that
chains many tool calls toward a goal, carrying memory between steps. Every
weakness from Pillar 2 still applies, and the loop adds four of its own --
the goal can be hijacked mid-run, poisoned data can be written to memory and
fire on a later step, the loop can run away, and a chain of individually-small
actions can add up to one irreversible one with no human in the way.

  collect_live()  turns the deployed agent runtime into a plain posture snapshot
                  (is the goal locked, is memory guardrailed, is there a step
                  budget, do tools hold their own least-privilege roles, is
                  there a human approval gate for high-impact actions, and is
                  every step audited into the Ch10 SOC).
  run_checks()    judges the snapshot and returns the gaps.

Unlocked profile -> 6 gaps. Locked profile -> 0. One flag set flips it.

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
    ("goal-lock", "HIGH",
     "The agent's goal is mutable. Injected content can redirect the run "
     "mid-loop (goal hijacking, LLM01 amplified across steps)."),
    ("memory-guardrail", "HIGH",
     "Agent memory is written unchecked. A poisoned note persists and fires "
     "on a later step (indirect injection through memory, LLM01/LLM08)."),
    ("tool-least-priv", "HIGH",
     "Tools share one broad role across the whole chain. Excessive agency "
     "compounds -- one hijacked step can do everything (LLM06)."),
    ("step-budget", "MEDIUM",
     "No cap on steps or tool calls per run. The loop can run away "
     "(cost/DoS, and more attempts for an attacker)."),
    ("hitl-approval", "HIGH",
     "No human-in-the-loop gate on high-impact/irreversible actions. The "
     "agent can delete, pay, or send with no review (LLM06 / insecure output)."),
    ("run-audit", "MEDIUM",
     "Agent steps and decisions are not audited into the SOC. Autonomous "
     "abuse is invisible after the fact."),
]

SNAPSHOT_KEY = {
    "goal-lock": "goal_locked",
    "memory-guardrail": "memory_guardrail",
    "tool-least-priv": "tool_least_priv",
    "step-budget": "step_budget",
    "hitl-approval": "hitl_approval",
    "run-audit": "run_audit",
}


def run_checks(snapshot: dict) -> list[dict]:
    gaps = []
    for key, sev, msg in CHECKS:
        if not snapshot.get(SNAPSHOT_KEY[key], False):
            gaps.append({"check": key, "severity": sev, "message": msg})
    return gaps


def collect_live(project: str, region: str) -> dict:
    """Read the real posture. In the lab this reads the posture file the
    Terraform emits; on a real account you would extend this to describe the
    agent runtime's goal handling, the memory store's guardrail, the step
    limiter, each tool role, the approval queue, and the audit wiring via
    boto3. Falls back to the unlocked posture."""
    path = os.environ.get(
        "HWZ_AGENT_POSTURE",
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
_CONSOLE_CARD = 'Agent Loop'
_CONSOLE_META = 'Chapter 13 · Pillar 3: Agentic'
_CONSOLE_WEAK = '5/5 abuses succeeded'
_CONSOLE_HARD = '0/5 — each died at a different lock'
_CONSOLE_UNIT = 'loop-control gap(s)'
_CONSOLE_WLINE = 'the loop turned against you'
_CONSOLE_HLINE = 'goal locked, memory guarded, loop bounded, human-gated'


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
        print("PASS. The goal is locked, memory is guarded, the loop is "
              "bounded, tools are least-privilege, and a human gates every "
              "irreversible action.")
        return 0
    print(f"NAKED. {len(gaps)} gap(s):\n")
    for g in gaps:
        print(f"  [{g['severity']:<6}] {g['check']:<17} {g['message']}")
    return 1


UNLOCKED = {k: False for k in SNAPSHOT_KEY.values()}
LOCKED = {k: True for k in SNAPSHOT_KEY.values()}


def selftest() -> int:
    u = run_checks(UNLOCKED)
    l = run_checks(LOCKED)
    print(f"selftest: unlocked fixture -> {len(u)} gaps (expected 6)")
    print(f"selftest: locked fixture   -> {len(l)} gaps (expected 0)")
    ok = len(u) == 6 and len(l) == 0
    print("selftest: PASS" if ok else "selftest: FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="hwz-scan: Agentic-AI posture check (Pillar 3).")
    ap.add_argument("--project", default="hwz")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return report(run_checks(collect_live(args.project, args.region)))


if __name__ == "__main__":
    sys.exit(main())
