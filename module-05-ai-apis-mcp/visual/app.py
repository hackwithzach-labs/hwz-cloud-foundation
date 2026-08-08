#!/usr/bin/env python3
"""
Chapter 12 — AI APIs and MCP Security, as a visual lab.

Five tool controls as cards, judged by the SAME scan/scan.py your terminal
runs. The headline number of this chapter is 5 -> 0.

This scanner reads the posture file Terraform writes on apply, not the AWS API,
so the lab needs no credentials — but it still follows your deploy: run
`terraform apply -var-file=hardened.tfvars` and refresh.

    pip install flask
    python app.py           # http://localhost:5112

(c) 2026 Vigilantia Technologies INC. TM HackWithZach.
"""
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_DIR.parent / "scan"))
sys.path.insert(0, str(APP_DIR))

import scan as scanner            # noqa: E402
from hwzvisual import VisualLab   # noqa: E402

# Build the two demo postures from the scanner's own key map, so a new check
# added to scan.py automatically appears here instead of being silently
# omitted from the samples.
WEAK = {k: False for k in scanner.SNAPSHOT_KEY.values()}
HARD = {k: True for k in scanner.SNAPSHOT_KEY.values()}

CARDS = [
    {"key": "mcp-auth", "name": "MCP Authentication", "chain": "who may drive the tools",
     "why": "An unauthenticated MCP server is a remote control for your tools, left on the table. Anyone who can reach it can drive them."},
    {"key": "tool-least-priv", "name": "Per-Tool Least Privilege", "chain": "one tool, one job",
     "why": "The whole pillar in one flag. Off, every tool runs under one broad identity and a single hijacked call reaches everything. On, a hijack is contained to that tool's job."},
    {"key": "toolcall-guardrail", "name": "Tool-Call Guardrail", "chain": "arguments and results",
     "why": "A tool result is untrusted input. Without a guardrail on the way out and the way back, a poisoned result becomes the next instruction."},
    {"key": "tool-allowlist", "name": "Tool Allowlist + Schema", "chain": "only these, only this shape",
     "why": "A registered-tool allowlist with argument schemas. Anything not on the list cannot be called, and anything malformed does not reach the tool."},
    {"key": "egress-locked", "name": "Egress Lock", "chain": "where a tool may reach",
     "why": "Open internet egress from a tool is SSRF and exfiltration waiting for an excuse. Lock it and the interesting attacks stop being possible."},
]

lab = VisualLab(
    scanner=scanner,
    chapter=12,
    pillar="Pillar 2 — AI APIs & MCP",
    title="MCP Tool Abuse — 5 gaps to 0",
    subtitle="Five controls between a model and the tools it can reach.",
    cards=CARDS,
    weak_word="ABUSED",
    hard_word="CONTAINED",
    weak_line="The tools are reachable and over-privileged. One hijacked call reaches everything.",
    hard_line="All five controls wired. A hijacked tool call is contained to that tool's job.",
    cli_hint="python scan/scan.py --project hwz --region us-east-1",
    chain_footer="A tool is a hand reaching out of the sandbox. <b>Five controls decide how far it can reach.</b>",
    demo_snapshots={"weak": WEAK, "hardened": HARD},
    needs_aws=False,
)

app = lab.flask_app()

if __name__ == "__main__":
    lab.run()
