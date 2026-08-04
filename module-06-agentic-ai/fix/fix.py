#!/usr/bin/env python3
"""
fix.py  -  hwz-harden for Module 6 (Pillar 3, Agentic AI). The automated
remediation, the live-account partner to `terraform apply -var-file=hardened.tfvars`.

It turns on every loop control: lock the goal, guardrail memory writes, give
each tool its own least-privilege role, bound the loop with a step budget, put
a human in front of every irreversible action, and audit every step into the
Ch10 SOC. In the lab it writes the locked posture the scanner reads; on a real
account you extend the marked section to wire these into your agent runtime.
Idempotent.

    python3 fix/fix.py --project hwz --region us-east-1
    python3 scan/scan.py --project hwz --region us-east-1     # now PASS

(c) 2026 Vigilantia Technologies INC. HackWithZach. Education/defense only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

LOCKED = {
    "goal_locked": True,
    "memory_guardrail": True,
    "tool_least_priv": True,
    "step_budget": True,
    "hitl_approval": True,
    "run_audit": True,
}

POSTURE = os.environ.get(
    "HWZ_AGENT_POSTURE",
    os.path.join(os.path.dirname(__file__), "..", "scan", "posture.json"))


def selftest() -> int:
    """Prove, with no AWS, that the posture this harden writes makes the
    scanner report zero -- the same contract every other module's fix ships."""
    import importlib.util
    here = os.path.dirname(__file__)
    spec = importlib.util.spec_from_file_location(
        "hwz_scan_m6", os.path.join(here, "..", "scan", "scan.py"))
    scan = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scan)
    unlocked = {k: False for k in LOCKED}
    before = scan.run_checks(unlocked)
    after = scan.run_checks(dict(LOCKED))
    print(f"selftest: unlocked posture -> {len(before)} gaps (expected > 0)")
    print(f"selftest: locked   posture -> {len(after)} gaps (expected 0)")
    ok = len(before) > 0 and len(after) == 0
    print("hwz-harden selftest:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="hwz-harden: lock the agent loop.")
    ap.add_argument("--project", default="hwz")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--selftest", action="store_true",
                    help="Prove the harden closes every scan gap, no AWS.")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    # ---- On a real account, this is where you would: -----------------------
    #   * pin the system goal outside model-editable context (goal_locked)
    #   * run every memory write through agentguard.memory_guardrail
    #   * give each tool its OWN least-privilege role (from Pillar 2)
    #   * enforce a per-run step/tool-call budget in the orchestrator
    #   * route high-impact actions to an approval queue (hitl_approval)
    #   * emit every step + decision to the Ch10 log group (run_audit)
    os.makedirs(os.path.dirname(POSTURE), exist_ok=True)
    before = json.load(open(POSTURE)) if os.path.exists(POSTURE) else {}
    with open(POSTURE, "w") as f:
        json.dump(LOCKED, f, indent=2)

    changed = [k for k, v in LOCKED.items() if not before.get(k, False)]
    print("hardened: enabled " + ", ".join(changed) if changed
          else "hardened: already fully locked (no-op)")
    print("Run: python3 scan/scan.py  ->  expect PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
