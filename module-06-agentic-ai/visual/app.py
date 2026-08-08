#!/usr/bin/env python3
"""
Chapter 13 — Agentic AI Security, as a visual lab.

Six loop controls as cards, judged by the SAME scan/scan.py your terminal runs.
BREACH to BLOCKED.

    pip install flask
    python app.py           # http://localhost:5113

(c) 2026 Vigilantia Technologies INC. TM HackWithZach.
"""
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_DIR.parent / "scan"))
sys.path.insert(0, str(APP_DIR))

import scan as scanner            # noqa: E402
from hwzvisual import VisualLab   # noqa: E402

WEAK = {k: False for k in scanner.SNAPSHOT_KEY.values()}
HARD = {k: True for k in scanner.SNAPSHOT_KEY.values()}

CARDS = [
    {"key": "goal-lock", "name": "Goal Lock", "chain": "the objective itself",
     "why": "The agent carries its goal into every pass of the loop. If a poisoned observation can rewrite it, one injected sentence redirects the entire run."},
    {"key": "memory-guardrail", "name": "Memory Guardrail", "chain": "notes written, notes read",
     "why": "A note written this step is read on a later step. An unchecked memory write is a delayed-action injection that fires after you stopped watching."},
    {"key": "tool-least-priv", "name": "Per-Tool Least Privilege", "chain": "blast radius per step",
     "why": "One broad role across the whole chain means excessive agency compounds. Scoped per tool, a hijacked step cannot cascade."},
    {"key": "step-budget", "name": "Step Budget", "chain": "how long it may run",
     "why": "An uncapped loop is a runaway bill and, worse, unlimited attempts for an attacker who only needs one to land."},
    {"key": "hitl-approval", "name": "Human In The Loop", "chain": "the irreversible act",
     "why": "Delete, pay, send externally. The last gate before an autonomous system does something you cannot take back."},
    {"key": "run-audit", "name": "Run Audit", "chain": "steps -> the SOC",
     "why": "Agent decisions audited into Chapter 10's detection chain. Without it, autonomous abuse is invisible after the fact."},
]

lab = VisualLab(
    scanner=scanner,
    chapter=13,
    pillar="Pillar 3 — Agentic",
    title="Agent Loop — BREACH to BLOCKED",
    subtitle="Four attack points on a loop, and the six controls that hold them.",
    cards=CARDS,
    weak_word="BREACH",
    hard_word="BLOCKED",
    weak_line="The loop is steerable. A single poisoned step becomes an autonomous campaign.",
    hard_line="Every loop control wired. One poisoned step stays one poisoned step.",
    cli_hint="python scan/scan.py --project hwz --region us-east-1",
    chain_footer="A single tool call is one decision. <b>A loop is a chain, and state carries the compromise forward.</b>",
    demo_snapshots={"weak": WEAK, "hardened": HARD},
    needs_aws=False,
)

app = lab.flask_app()

if __name__ == "__main__":
    lab.run()
