#!/usr/bin/env python3
"""
scan.py — the capstone scan: every pillar, one report.

Three things this does, and they answer three different questions.

  --profile weak|hardened   What is the posture of the whole stack?
  --posture posture.json    ...read from what Terraform actually deployed.
  --green-wall              Does every module in the course still prove itself?

The green wall is the one worth explaining. It runs every other module's
offline `--selftest` in sequence. No AWS, no credentials, no cost, and it is
the single most useful artifact in your portfolio: a repository that proves
itself on a laptop with no account attached. Anyone can clone it and watch it
pass. That is a much stronger claim than a screenshot of your own console.

    python3 scan/scan.py --profile weak
    python3 scan/scan.py --profile hardened
    python3 scan/scan.py --green-wall
    python3 scan/scan.py --selftest

Exit 0 clean, 1 findings. (c) 2026 Vigilantia Technologies INC. HackWithZach.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_DIR = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(MODULE_DIR)

# The capstone's control map. Each row is a control, the pillar it came from,
# and the chapter that built it -- so a finding always points back to the
# lesson that explains it. A finding you cannot trace to a chapter is a finding
# a student cannot act on.
CONTROLS = [
    ("guardrail",       "Pillar 1", 11, "HIGH",
     "Input guardrail on every ingested source. Without it, poisoned document text reaches the model."),
    ("goal-lock",       "Pillar 3", 13, "HIGH",
     "Standing objective is not model-editable. Without it, one injected sentence redirects the whole run."),
    ("tool-least-priv", "Pillar 2", 12, "HIGH",
     "Each tool bound to the session identity. Without it, lookup_account reads the table instead of a row."),
    ("hitl-approval",   "Pillar 3", 13, "HIGH",
     "A human gates every irreversible action. Without it, an external send fires unattended."),
    ("run-audit",       "Pillar 1", 10, "MEDIUM",
     "Agent decisions reach the SOC. Without it, the breach still happens and nobody finds out."),
    ("foundation-pinned", "Cloud",   8, "HIGH",
     "The composed foundation deploys hardened, never weak. Only the new layer starts weak."),
]

# Every module's offline proof. Path relative to the repo root, then the args.
GREEN_WALL = [
    ("module-01-cloud-foundation/scan",        "scan.py"),
    ("module-02-api-security/attack",          "attack.py"),
    ("module-03-observability-detection/detect", "detect.py"),
    ("module-03-observability-detection/attack", "emit.py"),
    ("module-04-llm-security/guard",           "guard.py"),
    ("module-04-llm-security/scan",            "scan.py"),
    ("module-05-ai-apis-mcp/scan",             "scan.py"),
    ("module-06-agentic-ai/scan",              "scan.py"),
    ("module-07-vibe-coding/scan",             "scan.py"),
    ("module-08-capstone/attack",              "end_to_end.py"),
    ("module-04-llm-security/visual",          "ipi_scan.py"),
]


def posture_weak():
    return {name: False for name, *_ in CONTROLS}


def posture_hardened():
    return {name: True for name, *_ in CONTROLS}


def run_checks(posture):
    """Pure function over a plain dict. No AWS, so it is testable for free."""
    findings = []
    for name, pillar, chapter, sev, why in CONTROLS:
        if not posture.get(name):
            findings.append((sev, pillar, f"ch{chapter}", name, why))
    order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    findings.sort(key=lambda f: -order[f[0]])
    return findings


def report(findings, source):
    if not findings:
        print(f"PASS. Every pillar wired. ({source})")
        print("\nThe same payload that completed the chain ten minutes ago now dies")
        print("at the first lock, and the SOC sees it. Run:")
        print("  python3 attack/end_to_end.py --ticket attack/tickets/poisoned.pdf --hardened")
        return 0
    print(f"NAKED. {len(findings)} gap(s) across the stack. ({source})\n")
    for sev, pillar, ch, name, why in findings:
        print(f"  [{sev:<6}] {pillar:<10} {ch:<5} {name:<19} {why}")
    print(f"\nEvery gap above is a chapter you have already done. Nothing here is new;")
    print("the capstone is only the first time they are all standing at once.")
    return 1


def green_wall():
    """Run every module's offline selftest and print the wall."""
    print("Every module in this course, proving itself. No AWS, no credentials,")
    print("no cost. This is the artifact to put in front of a hiring manager.\n")
    width = max(len(d) for d, _ in GREEN_WALL) + 2
    passed = failed = missing = 0
    for rel, script in GREEN_WALL:
        d = os.path.join(REPO_ROOT, rel)
        path = os.path.join(d, script)
        label = f"{rel}/{script}"
        if not os.path.exists(path):
            print(f"  MISSING  {label}")
            missing += 1
            continue
        try:
            r = subprocess.run([sys.executable, script, "--selftest"], cwd=d,
                               capture_output=True, text=True, timeout=180)
            ok = r.returncode == 0
        except subprocess.TimeoutExpired:
            ok = False
            r = None
        if ok:
            print(f"  PASS     {label}")
            passed += 1
        else:
            print(f"  FAIL     {label}")
            # Show why. A green wall that hides its failures is a wall, not a proof.
            if r is not None:
                for line in (r.stdout + r.stderr).strip().splitlines()[-4:]:
                    print(f"             {line}")
            failed += 1

    print(f"\n{passed} passed, {failed} failed, {missing} missing.")
    if missing:
        print("MISSING means the module is not in this clone. That is not a pass.")
    return 0 if (failed == 0 and missing == 0) else 1


def selftest():
    ok = True

    def check(label, cond):
        nonlocal ok
        print(f"selftest: {label:<52}{'ok' if cond else 'FAIL'}")
        if not cond:
            ok = False

    weak = run_checks(posture_weak())
    hard = run_checks(posture_hardened())
    check(f"weak posture -> {len(weak)} gap(s)", len(weak) == len(CONTROLS))
    check("hardened posture -> 0 gaps", hard == [])
    check("every control names a real chapter",
          all(isinstance(c[2], int) and 8 <= c[2] <= 15 for c in CONTROLS))

    # A partial posture must report exactly what is missing, not round to weak.
    partial = posture_hardened()
    partial["hitl-approval"] = False
    f = run_checks(partial)
    check("one control off -> exactly one finding", len(f) == 1 and f[0][3] == "hitl-approval")

    # The green wall list must not name a module that does not exist, or the
    # wall silently shrinks as the repo changes.
    absent = [f"{d}/{s}" for d, s in GREEN_WALL
              if not os.path.exists(os.path.join(REPO_ROOT, d, s))]
    check(f"green-wall list all present ({len(GREEN_WALL)} entries)", not absent)
    for a in absent:
        print(f"          missing: {a}")

    print("selftest:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="Capstone scan: every pillar, one report.")
    ap.add_argument("--profile", choices=["weak", "hardened"])
    ap.add_argument("--posture", help="posture.json written by terraform apply")
    ap.add_argument("--green-wall", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if args.green_wall:
        return green_wall()
    if args.posture:
        with open(args.posture, encoding="utf-8") as fh:
            data = json.load(fh)
        posture = {name: bool(data.get(name, False)) for name, *_ in CONTROLS}
        return report(run_checks(posture), os.path.basename(args.posture))
    if args.profile:
        posture = posture_weak() if args.profile == "weak" else posture_hardened()
        return report(run_checks(posture), f"{args.profile} profile (bundled sample)")

    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
