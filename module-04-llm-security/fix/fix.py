#!/usr/bin/env python3
"""
fix.py  -  hwz-harden for Module 4. The automated remediation, the live-account
partner to `terraform apply -var-file=hardened.tfvars`.

It turns on both firewalls for the LLM layer: the input guardrail, the output
guardrail, the instruction/data boundary, and the WAF web ACL + rate rule. In
the lab it writes the hardened posture the scanner reads; on a real account you
extend the marked section to enable Bedrock Guardrails and associate the WAF
web ACL via boto3. Idempotent: run it twice and the second run is a no-op.

    python3 fix/fix.py --project hwz --region us-east-1
    python3 scan/scan.py --project hwz --region us-east-1     # now PASS

(c) 2026 Vigilantia Technologies INC. HackWithZach. Education/defense only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HARDENED = {
    "input_guardrail": True,
    "output_guardrail": True,
    "instruction_data_boundary": True,
    "waf_web_acl": True,
    "waf_rate_rule": True,
}

POSTURE = os.environ.get(
    "HWZ_LLM_POSTURE",
    os.path.join(os.path.dirname(__file__), "..", "scan", "posture.json"))


def main() -> int:
    ap = argparse.ArgumentParser(description="hwz-harden: enable the LLM guardrail + WAF.")
    ap.add_argument("--project", default="hwz")
    ap.add_argument("--region", default="us-east-1")
    args = ap.parse_args()

    # ---- On a real account, this is where you would: -----------------------
    #   * create/attach a Bedrock Guardrail (denied topics, PII, content filter)
    #   * associate the WAF web ACL with the API's ALB / API Gateway stage
    #   * point WAF logging at the Module 3 CloudWatch log group
    # The lab records the resulting posture so scan.py reflects reality.
    os.makedirs(os.path.dirname(POSTURE), exist_ok=True)
    before = {}
    if os.path.exists(POSTURE):
        before = json.load(open(POSTURE))
    with open(POSTURE, "w") as f:
        json.dump(HARDENED, f, indent=2)

    changed = [k for k, v in HARDENED.items() if not before.get(k, False)]
    if changed:
        print("hardened: enabled " + ", ".join(changed))
    else:
        print("hardened: already fully wired (no-op)")
    print("Run: python3 scan/scan.py  ->  expect PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
