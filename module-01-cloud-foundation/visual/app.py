#!/usr/bin/env python3
"""
Chapter 8 — Cloud Foundation, as a visual lab.

Six control families as cards, scanned by the SAME scan/scan.py your terminal
runs. Nothing here talks to AWS or re-checks anything; it imports the scanner
and renders it.

    pip install flask boto3
    python app.py           # http://localhost:5108

(c) 2026 Vigilantia Technologies INC. TM HackWithZach.
"""
import json
import os
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_DIR.parent / "scan"))
sys.path.insert(0, str(APP_DIR))

import scan as scanner            # noqa: E402  the module's own scanner
from hwzvisual import VisualLab   # noqa: E402


def fixture(name):
    p = APP_DIR.parent / "scan" / "fixtures" / name
    if p.exists():
        with open(p) as fh:
            return json.load(fh)
    return {}


CARDS = [
    {"key": "s3", "name": "S3 Buckets", "chain": "data at rest",
     "why": "Encryption, Block Public Access, TLS-only policy and versioning. The four settings behind most public-bucket headlines."},
    {"key": "sg", "name": "Security Groups", "chain": "the front door",
     "why": "Ingress from 0.0.0.0/0 is the single most common way an account gets found by a scanner that was not looking for you."},
    {"key": "vpc", "name": "VPC Flow Logs", "chain": "traffic -> evidence",
     "why": "You cannot investigate traffic you never recorded. This is the network half of Chapter 10's detection chain."},
    {"key": "iam", "name": "IAM", "chain": "who can do what",
     "why": "Scoped workload roles and a deny on destructive actions. Identity is the perimeter now; a wildcard here undoes everything else."},
    {"key": "kms", "name": "KMS", "chain": "keys and their policy",
     "why": "A customer-managed key with a strict policy. Encryption you do not control the key for is encryption someone else controls."},
    {"key": "cloudtrail", "name": "CloudTrail", "chain": "the record itself",
     "why": "Multi-region, log-file validation, data events, KMS. If the trail is weak, every later chapter is investigating a fiction."},
]

lab = VisualLab(
    scanner=scanner,
    chapter=8,
    pillar="Pillar: Cloud",
    title="Cloud Foundation — weak vs hardened",
    subtitle="Six control families. The ground every later chapter stands on.",
    cards=CARDS,
    weak_word="WEAK",
    hard_word="HARDENED",
    weak_line="The foundation has holes. Everything you build on it inherits them.",
    hard_line="Every control family clean. This is the ground the rest of the course composes onto.",
    cli_hint="python scan/scan.py --project hwz --region us-east-1",
    chain_footer="Six families, one question: <b>if someone got in tonight, what would they reach, and could you prove what they touched?</b>",
    # The SAME fixtures scan.py --selftest judges. One fixture set, one scanner.
    demo_snapshots={"weak": lambda: fixture("insecure.json"),
                    "hardened": lambda: fixture("secure.json")},
)

app = lab.flask_app()

if __name__ == "__main__":
    lab.run()
