#!/usr/bin/env python3
"""
hwz-scan :: the secure script that proves your foundation is insecure.

How the course uses it:
  1. You deploy the WEAK stack.
  2. You run this scanner. It reads the LIVE account and fails loudly.
     Every FAIL is a real hole you can see in the console.
  3. You harden the stack.
  4. You run this scanner again. The findings clear.

The scanner separates AWS reading from the checks on purpose. collect_live()
turns your account into a plain snapshot dict. run_checks() judges the snapshot.
That means you can test the checks with no AWS at all: `python scan.py --selftest`
runs them against a known-insecure and known-secure fixture and proves the logic.

Only resources tagged Project=<project> are scanned, so the scanner never
touches anything but your lab.

(C) 2026 Vigilantia Technologies INC. All rights reserved.
"""
import argparse, json, sys, os

SEV = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


# ---------------------------------------------------------------------------
# CHECKS  (pure functions over a snapshot dict; no AWS in here)
# ---------------------------------------------------------------------------
def check_s3(snap):
    f = []
    for b in snap.get("s3_buckets", []):
        name = b["name"]
        if not b.get("default_encryption"):
            f.append(("HIGH", "s3", name, "No default encryption. Objects stored in the clear."))
        if not b.get("block_public_access"):
            f.append(("HIGH", "s3", name, "No Block Public Access. Bucket can be exposed to the internet."))
        if not b.get("tls_only_policy"):
            f.append(("MEDIUM", "s3", name, "No TLS-only bucket policy. Plaintext requests accepted."))
        if not b.get("versioning"):
            f.append(("LOW", "s3", name, "Versioning off. No recovery from overwrite or delete."))
    return f


def check_security_groups(snap):
    f = []
    for sg in snap.get("security_groups", []):
        for rule in sg.get("ingress", []):
            if rule.get("cidr") == "0.0.0.0/0":
                f.append(("HIGH", "sg", sg["id"],
                          f"Ingress on port {rule.get('port')} open to 0.0.0.0/0."))
    return f


def check_vpc_flow_logs(snap):
    f = []
    for v in snap.get("vpcs", []):
        if not v.get("flow_logs"):
            f.append(("MEDIUM", "vpc", v["id"], "No VPC flow logs. You cannot investigate traffic you never recorded."))
    return f


def check_iam(snap):
    f = []
    for r in snap.get("iam_roles", []):
        if r.get("has_wildcard_allow"):
            f.append(("HIGH", "iam", r["name"], "Role policy allows wildcard or service-wide actions (s3:*, kms:*)."))
        if not r.get("has_destructive_deny"):
            f.append(("MEDIUM", "iam", r["name"], "No explicit deny on destructive actions (delete bucket, stop trail, delete key)."))
    return f


def check_kms(snap):
    f = []
    for k in snap.get("kms_keys", []):
        if not k.get("rotation"):
            f.append(("MEDIUM", "kms", k["id"], "Key rotation disabled."))
    return f


def check_cloudtrail(snap):
    f = []
    trails = snap.get("cloudtrails", [])
    if not trails:
        f.append(("HIGH", "cloudtrail", "-", "No CloudTrail found. The account has no audit record."))
    for t in trails:
        name = t["name"]
        if not t.get("multi_region"):
            f.append(("MEDIUM", "cloudtrail", name, "Trail is single-region. Activity in other regions is invisible."))
        if not t.get("log_file_validation"):
            f.append(("MEDIUM", "cloudtrail", name, "Log file validation off. Log tampering is undetectable."))
        if not t.get("data_events"):
            f.append(("MEDIUM", "cloudtrail", name, "No S3 data events. Object reads and writes are not recorded."))
        if not t.get("kms_encrypted"):
            f.append(("LOW", "cloudtrail", name, "Trail logs not encrypted with a customer-managed key."))
    return f


ALL_CHECKS = [check_s3, check_security_groups, check_vpc_flow_logs,
              check_iam, check_kms, check_cloudtrail]


def run_checks(snap):
    findings = []
    for c in ALL_CHECKS:
        findings.extend(c(snap))
    findings.sort(key=lambda x: -SEV[x[0]])
    return findings


# ---------------------------------------------------------------------------
# LIVE COLLECTION  (boto3; only imported when actually scanning an account)
# ---------------------------------------------------------------------------
def collect_live(project, region):
    import boto3
    tagval = project
    snap = {"s3_buckets": [], "security_groups": [], "vpcs": [],
            "iam_roles": [], "kms_keys": [], "cloudtrails": []}

    s3 = boto3.client("s3", region_name=region)
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        # scope to lab buckets by tag
        try:
            tags = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=name).get("TagSet", [])}
        except Exception:
            tags = {}
        if tags.get("Project") != tagval:
            continue
        enc = pab = tls = ver = False
        try:
            s3.get_bucket_encryption(Bucket=name); enc = True
        except Exception: pass
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            pab = all(cfg.values())
        except Exception: pass
        try:
            pol = s3.get_bucket_policy(Bucket=name)["Policy"]
            tls = "aws:SecureTransport" in pol
        except Exception: pass
        try:
            ver = s3.get_bucket_versioning(Bucket=name).get("Status") == "Enabled"
        except Exception: pass
        snap["s3_buckets"].append({"name": name, "default_encryption": enc,
                                   "block_public_access": pab, "tls_only_policy": tls, "versioning": ver})

    ec2 = boto3.client("ec2", region_name=region)
    flt = [{"Name": "tag:Project", "Values": [tagval]}]
    for sg in ec2.describe_security_groups(Filters=flt).get("SecurityGroups", []):
        ingress = []
        for p in sg.get("IpPermissions", []):
            for rng in p.get("IpRanges", []):
                ingress.append({"port": p.get("FromPort"), "cidr": rng.get("CidrIp")})
        snap["security_groups"].append({"id": sg["GroupId"], "ingress": ingress})

    for v in ec2.describe_vpcs(Filters=flt).get("Vpcs", []):
        fl = ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [v["VpcId"]]}]).get("FlowLogs", [])
        snap["vpcs"].append({"id": v["VpcId"], "flow_logs": len(fl) > 0})

    iam = boto3.client("iam")
    for r in iam.list_roles().get("Roles", []):
        name = r["RoleName"]
        if not name.startswith(project):
            continue
        wild = destructive_deny = False
        for pn in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            doc = iam.get_role_policy(RoleName=name, PolicyName=pn)["PolicyDocument"]
            for st in doc.get("Statement", []):
                acts = st.get("Action", [])
                acts = [acts] if isinstance(acts, str) else acts
                if st.get("Effect") == "Allow" and any(a == "*" or a.endswith(":*") for a in acts):
                    wild = True
                if st.get("Effect") == "Deny":
                    destructive_deny = True
        snap["iam_roles"].append({"name": name, "has_wildcard_allow": wild,
                                  "has_destructive_deny": destructive_deny})

    kms = boto3.client("kms", region_name=region)
    for k in kms.list_keys().get("Keys", []):
        kid = k["KeyId"]
        try:
            meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
            if meta.get("KeyManager") != "CUSTOMER":
                continue
            # A key scheduled for deletion is on its way out, not a live control.
            # After a teardown-and-redeploy the old key lingers in PendingDeletion
            # for its recovery window, still tagged; flagging its rotation is
            # noise about a key that no longer protects anything. Skip it.
            if meta.get("KeyState") in ("PendingDeletion", "PendingReplicaDeletion"):
                continue
            # Scope to this lab's own keys by tag, exactly like the S3, EC2, VPC
            # and CloudTrail collectors above. Without this the scanner reaches
            # OUT of your lab and flags every unrelated customer-managed key in
            # the account (an old experiment, another project) as a false
            # finding -- which breaks the promise at the top of this file that
            # "the scanner never touches anything but your lab".
            tags = {t["TagKey"]: t["TagValue"]
                    for t in kms.list_resource_tags(KeyId=kid).get("Tags", [])}
            if tags.get("Project") != tagval:
                continue
            rot = kms.get_key_rotation_status(KeyId=kid).get("KeyRotationEnabled", False)
            snap["kms_keys"].append({"id": kid, "rotation": rot})
        except Exception: pass

    ct = boto3.client("cloudtrail", region_name=region)
    for t in ct.describe_trails().get("trailList", []):
        if project not in t.get("Name", ""):
            continue
        sel = ct.get_event_selectors(TrailName=t["TrailARN"]).get("EventSelectors", [])
        data_ev = any(es.get("DataResources") for es in sel)
        snap["cloudtrails"].append({
            "name": t["Name"],
            "multi_region": t.get("IsMultiRegionTrail", False),
            "log_file_validation": t.get("LogFileValidationEnabled", False),
            "data_events": data_ev,
            "kms_encrypted": bool(t.get("KmsKeyId")),
        })
    return snap


# ---------------------------------------------------------------------------
# REPORT + CLI
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# LAB CONSOLE MAP  (added) — ties this CLI run to its card in the HWZ Lab
# Console, so terminal output and the dashboard are provably the same story.
#   findings (rc=1) -> the red card;   clean (rc=0) -> the green card.
# ---------------------------------------------------------------------------
_CONSOLE_CARD = 'Cloud Foundation'
_CONSOLE_META = 'Chapter 8 · Pillar: Cloud'
_CONSOLE_WEAK = 'NAKED'
_CONSOLE_HARD = 'PASS'
_CONSOLE_UNIT = 'finding(s)'
_CONSOLE_WLINE = 'the account is wide open'
_CONSOLE_HLINE = 'scoped, encrypted, logged, bounded'


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


def _report(findings):
    if not findings:
        print("PASS. No findings. This foundation is hardened.")
        return 0
    print(f"FAIL. {len(findings)} finding(s):\n")
    for sev, svc, res, msg in findings:
        print(f"  [{sev:6}] {svc:11} {res:22} {msg}")
    highs = sum(1 for f in findings if f[0] == "HIGH")
    print(f"\n{highs} HIGH severity. Fix these first. Then re-run this scanner.")
    return 1


def selftest():
    here = os.path.dirname(__file__)
    ok = True
    with open(os.path.join(here, "fixtures", "insecure.json")) as fh:
        ins = run_checks(json.load(fh))
    with open(os.path.join(here, "fixtures", "secure.json")) as fh:
        sec = run_checks(json.load(fh))
    print(f"selftest: insecure fixture -> {len(ins)} findings (expected > 0)")
    print(f"selftest: secure   fixture -> {len(sec)} findings (expected 0)")
    if len(ins) == 0:
        print("  ! insecure fixture produced no findings, checks are broken"); ok = False
    if len(sec) != 0:
        print("  ! secure fixture produced findings, checks are too strict:"); ok = False
        for x in sec: print("     ", x)
    print("selftest:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="hwz-scan: prove the foundation insecure, then prove it hardened")
    ap.add_argument("--project", default="hwz", help="Project tag / name prefix to scope the scan")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--snapshot", help="Scan a saved snapshot JSON instead of live AWS")
    ap.add_argument("--selftest", action="store_true", help="Run checks against fixtures, no AWS")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest())
    if a.snapshot:
        with open(a.snapshot) as fh:
            snap = json.load(fh)
    else:
        snap = collect_live(a.project, a.region)
    sys.exit(report(run_checks(snap)))


if __name__ == "__main__":
    main()
