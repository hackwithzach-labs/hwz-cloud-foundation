#!/usr/bin/env python3
"""
scan.py — the pre-deploy gate for Pillar 4 (vibe coding).

WHAT MAKES THIS MODULE DIFFERENT
--------------------------------
Every other module in this course scans an account. This one scans a *plan*,
before anything exists. That is the whole pillar: AI can generate insecure
infrastructure all day, and it never reaches an account, because the gate runs
before `terraform apply` and it cannot be skipped.

WHY IT IMPORTS THE CHAPTER 8 SCANNER INSTEAD OF DEFINING NEW CHECKS
-------------------------------------------------------------------
A wildcard is a wildcard. It does not become a different finding because a
model wrote it instead of a person, and a second set of check functions here
would be a second definition of "secure" that could drift from the one you
already trust. So this file contains no judgements at all. It contains a
TRANSLATOR: Terraform plan JSON in, the Chapter 8 snapshot shape out. The
verdict comes from `module-01-cloud-foundation/scan/scan.py`, unchanged.

That split is also what makes the gate arguable in a code review. When someone
asks why the build went red, the answer is not "our AI linter said so" -- it is
"this is the same control map we have applied since Chapter 8, applied earlier."

USAGE
-----
    python3 scan/scan.py --plan plan.json          # terraform show -json plan.out
    python3 scan/scan.py --snapshot fixtures/ai-generated-insecure.json
    python3 scan/scan.py --selftest                # offline, no AWS, no cost

Exit code 0 = clean, 1 = findings. That is what fails a CI build.

(c) 2026 Vigilantia Technologies INC. HackWithZach. Education/defense only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_ROOT = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(MODULE_ROOT)
CH8_SCANNER = os.path.join(REPO_ROOT, "module-01-cloud-foundation", "scan", "scan.py")


def load_ch8():
    """
    Import the Chapter 8 scanner by path.

    By path, not by `import scan`, because this file is also called scan.py and
    a plain import would find itself. The failure mode there is silent and
    confusing -- the gate would run with zero checks and pass everything -- so
    it is worth the six extra lines to be explicit.
    """
    if not os.path.exists(CH8_SCANNER):
        sys.exit(
            f"Cannot find the Chapter 8 scanner at {CH8_SCANNER}.\n"
            "This module scores generated infrastructure with the SAME checks you\n"
            "built in Chapter 8, so it needs the repo intact around it. Run it\n"
            "from inside a full clone of the course repository."
        )
    spec = importlib.util.spec_from_file_location("hwz_ch8_scan", CH8_SCANNER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# TRANSLATOR: terraform plan JSON -> the Chapter 8 snapshot shape
# ---------------------------------------------------------------------------
#
# `terraform show -json plan.out` gives you planned_values.root_module, with
# resources nested under child_modules. We walk the whole tree, then read the
# handful of resource types the Chapter 8 control map covers.
#
# Everything defaults to INSECURE until the plan proves otherwise. A missing
# `aws_s3_bucket_server_side_encryption_configuration` block is not "unknown",
# it is "not encrypted" -- same default-deny posture the live scanner uses when
# an AWS call throws.


def _walk_resources(module):
    """Yield every resource in a planned_values module tree, depth first."""
    for r in module.get("resources", []):
        yield r
    for child in module.get("child_modules", []):
        yield from _walk_resources(child)


def _wildcard_in_policy(doc):
    """
    True if an IAM policy document allows a wildcard or service-wide action.

    Accepts the policy as a JSON string (what Terraform usually plans) or as an
    already-parsed dict. Checks Action for "*" or anything ending ":*", and
    treats Resource "*" as an aggravating factor rather than a requirement --
    `s3:*` scoped to one bucket is still the finding Chapter 8 flags.
    """
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except (json.JSONDecodeError, TypeError):
            return False
    if not isinstance(doc, dict):
        return False
    for stmt in doc.get("Statement", []) or []:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for a in actions:
            if a == "*" or (isinstance(a, str) and a.endswith(":*")):
                return True
    return False


def _has_destructive_deny(doc):
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except (json.JSONDecodeError, TypeError):
            return False
    if not isinstance(doc, dict):
        return False
    for stmt in doc.get("Statement", []) or []:
        if isinstance(stmt, dict) and stmt.get("Effect") == "Deny":
            return True
    return False


def plan_to_snapshot(plan):
    """Turn a terraform plan JSON document into a Chapter 8 snapshot."""
    root = plan.get("planned_values", {}).get("root_module", {})
    resources = list(_walk_resources(root))

    buckets = {}
    roles = {}
    keys = {}
    sgs = {}
    vpcs = {}

    def bucket(name):
        return buckets.setdefault(name, {
            "name": name,
            "default_encryption": False,
            "block_public_access": False,
            "tls_only_policy": False,
            "versioning": False,
        })

    for r in resources:
        t = r.get("type", "")
        v = r.get("values", {}) or {}

        if t == "aws_s3_bucket":
            bucket(v.get("bucket") or r.get("name", "generated-bucket"))

        elif t == "aws_s3_bucket_server_side_encryption_configuration":
            bucket(v.get("bucket", "generated-bucket"))["default_encryption"] = True

        elif t == "aws_s3_bucket_public_access_block":
            b = bucket(v.get("bucket", "generated-bucket"))
            # All four switches must be on. Three out of four is a public
            # bucket waiting for the fourth code path.
            b["block_public_access"] = all([
                v.get("block_public_acls"), v.get("block_public_policy"),
                v.get("ignore_public_acls"), v.get("restrict_public_buckets"),
            ])

        elif t == "aws_s3_bucket_versioning":
            cfg = v.get("versioning_configuration") or [{}]
            if isinstance(cfg, list):
                cfg = cfg[0] if cfg else {}
            bucket(v.get("bucket", "generated-bucket"))["versioning"] = (
                cfg.get("status") == "Enabled")

        elif t == "aws_s3_bucket_policy":
            b = bucket(v.get("bucket", "generated-bucket"))
            pol = v.get("policy", "")
            # The TLS-only pattern is a Deny on aws:SecureTransport false.
            b["tls_only_policy"] = "SecureTransport" in json.dumps(pol)

        elif t == "aws_iam_role":
            roles.setdefault(v.get("name") or r.get("name", "generated-role"), {
                "name": v.get("name") or r.get("name", "generated-role"),
                "has_wildcard_allow": False,
                "has_destructive_deny": False,
            })

        elif t in ("aws_iam_role_policy", "aws_iam_policy"):
            # Attach the verdict to the named role when we can tell, otherwise
            # to the only role in the plan. A generated module almost always
            # has exactly one.
            target = v.get("role") or (list(roles)[0] if roles else "generated-role")
            r_entry = roles.setdefault(target, {
                "name": target, "has_wildcard_allow": False,
                "has_destructive_deny": False})
            pol = v.get("policy", "")
            if _wildcard_in_policy(pol):
                r_entry["has_wildcard_allow"] = True
            if _has_destructive_deny(pol):
                r_entry["has_destructive_deny"] = True

        elif t == "aws_kms_key":
            keys[r.get("name", "generated-key")] = {
                "id": v.get("description") or r.get("name", "generated-key"),
                "rotation": bool(v.get("enable_key_rotation")),
            }

        elif t == "aws_security_group":
            ingress = []
            for rule in v.get("ingress", []) or []:
                for cidr in rule.get("cidr_blocks", []) or []:
                    ingress.append({"port": rule.get("from_port"), "cidr": cidr})
            sgs[r.get("name", "generated-sg")] = {
                "id": v.get("name") or r.get("name", "generated-sg"),
                "ingress": ingress,
            }

        elif t == "aws_vpc":
            vpcs[r.get("name", "generated-vpc")] = {
                "id": v.get("tags", {}).get("Name") or r.get("name", "generated-vpc"),
                "flow_logs": False,
            }

        elif t == "aws_flow_log":
            for vpc in vpcs.values():
                vpc["flow_logs"] = True

    return {
        "s3_buckets": list(buckets.values()),
        "iam_roles": list(roles.values()),
        "kms_keys": list(keys.values()),
        "security_groups": list(sgs.values()),
        "vpcs": list(vpcs.values()),
        "cloudtrails": [],   # a generated app module is not expected to ship one
    }


# ---------------------------------------------------------------------------
# ACCOUNT-LEVEL vs ARTIFACT-LEVEL CHECKS
# ---------------------------------------------------------------------------
#
# Not every Chapter 8 check is answerable before deployment, and pretending
# otherwise makes the gate useless.
#
# `check_cloudtrail` asks "does this ACCOUNT have an audit trail?" Point it at a
# generated module that creates a bucket and a role and it reports HIGH, "no
# CloudTrail found" -- correctly, for an account, and meaninglessly, for a
# two-resource module. No amount of hardening that module will ever satisfy it,
# because a module is not supposed to ship an account-wide trail. A gate that
# cannot be satisfied gets switched off, and a switched-off gate protects
# nothing.
#
# So the artifact gate runs every check that can be answered from the artifact
# and DEFERS the account-level ones, by name, out loud. Deferred is not
# dropped: the account scan in Chapter 8 still runs, and still asks that
# question of the account where it makes sense.
ACCOUNT_LEVEL = {"check_cloudtrail"}


def artifact_checks(ch8):
    """The Chapter 8 checks that a pre-deploy artifact can actually answer."""
    run, deferred = [], []
    for c in ch8.ALL_CHECKS:
        (deferred if c.__name__ in ACCOUNT_LEVEL else run).append(c)
    return run, deferred


def run_artifact_checks(ch8, snap):
    run, _ = artifact_checks(ch8)
    findings = []
    for c in run:
        findings.extend(c(snap))
    findings.sort(key=lambda x: -ch8.SEV[x[0]])
    return findings


def report(findings, source, deferred):
    if deferred:
        names = ", ".join(sorted(d.__name__ for d in deferred))
        print(f"(deferred to the account scan, not answerable pre-deploy: {names})\n")
    if not findings:
        print(f"PASS. No findings in {source}. Safe to apply.")
        return 0
    highs = sum(1 for f in findings if f[0] == "HIGH")
    print(f"NAKED. {len(findings)} gap(s) in {source}:\n")
    for sev, svc, res, msg in findings:
        print(f"  [{sev:<6}] {svc:<10} {res:<20} {msg}")
    print(f"\n{highs} HIGH finding(s). This generation must not reach an account.")
    return 1


def selftest():
    """Offline proof that the gate tells known-bad from known-good."""
    ch8 = load_ch8()
    ok = True

    for name, expect_clean in (("ai-generated-insecure.json", False),
                               ("ai-generated-hardened.json", True)):
        path = os.path.join(HERE, "fixtures", name)
        with open(path, encoding="utf-8") as fh:
            snap = json.load(fh)
        findings = run_artifact_checks(ch8, snap)
        clean = not findings
        state = "PASS" if clean else f"{len(findings)} gap(s)"
        print(f"selftest: {name:<30} -> {state}")
        if clean != expect_clean:
            print(f"selftest: FAIL — expected {'clean' if expect_clean else 'findings'}")
            ok = False

    # The deferral list is itself a claim, so test it. If someone later adds a
    # check name to ACCOUNT_LEVEL that does not exist, the gate would silently
    # run one fewer check than it reports.
    run, deferred = artifact_checks(ch8)
    known = {c.__name__ for c in ch8.ALL_CHECKS}
    unknown = ACCOUNT_LEVEL - known
    if unknown:
        print(f"selftest: FAIL — ACCOUNT_LEVEL names nothing in the Chapter 8 "
              f"scanner: {sorted(unknown)}")
        ok = False
    else:
        print(f"selftest: check split                 -> {len(run)} run, "
              f"{len(deferred)} deferred to the account scan")

    # The translator has to be tested too, or a plan could quietly produce an
    # empty snapshot and an empty snapshot passes every check.
    plan_path = os.path.join(HERE, "fixtures", "plan-weak.json")
    with open(plan_path, encoding="utf-8") as fh:
        snap = plan_to_snapshot(json.load(fh))
    n_buckets, n_roles = len(snap["s3_buckets"]), len(snap["iam_roles"])
    print(f"selftest: plan translator            -> {n_buckets} bucket(s), {n_roles} role(s)")
    if n_buckets < 1 or n_roles < 1:
        print("selftest: FAIL — translator produced an empty snapshot. An empty "
              "snapshot passes every check, which is the dangerous way to fail.")
        ok = False
    findings = run_artifact_checks(ch8, snap)
    if not findings:
        print("selftest: FAIL — the deliberately weak plan produced no findings.")
        ok = False
    else:
        print(f"selftest: weak plan via translator   -> {len(findings)} gap(s)")

    print("selftest:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="Pre-deploy gate for generated infrastructure.")
    ap.add_argument("--plan", help="terraform show -json output")
    ap.add_argument("--snapshot", help="a Chapter 8 style snapshot JSON")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    ch8 = load_ch8()
    if args.plan:
        with open(args.plan, encoding="utf-8") as fh:
            snap = plan_to_snapshot(json.load(fh))
        _, deferred = artifact_checks(ch8)
        return report(run_artifact_checks(ch8, snap), os.path.basename(args.plan), deferred)
    if args.snapshot:
        with open(args.snapshot, encoding="utf-8") as fh:
            snap = json.load(fh)
        _, deferred = artifact_checks(ch8)
        return report(run_artifact_checks(ch8, snap), os.path.basename(args.snapshot), deferred)

    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
