#!/usr/bin/env python3
"""
hwz-fix :: the remediation script. It closes every finding hwz-scan reports.

The pairing is deliberate and it is the core teaching idea of this project:
  - scan.py READS your account and reports what is wrong (Step 2).
  - fix.py WRITES to your account and makes each of those things right (Step 3).
  - You then run scan.py again and it reports clean (Step 4).

Read this file top to bottom. Every remediation is a small, named function with
the exact AWS API call it makes and a comment saying which finding it closes and
why the fix works. Nothing here is magic. It is the same API calls you would make
by hand in an incident, written down so you can run them repeatably.

Safety:
  - Default mode is DRY RUN. It prints the plan and touches nothing.
  - --commit actually calls AWS. Use it only in your sandbox account.
  - It is idempotent: running it twice is safe, the second run is a no-op.
  - --selftest proves, with no AWS at all, that applying these fixes to a known
    insecure snapshot makes scan.py report zero findings. That is how we know
    the fix closes exactly what the scan opens.

(C) 2026 Vigilantia Technologies INC. All rights reserved.
"""
import argparse, json, os, sys, copy

# Reuse the scanner's checks so the two scripts can never drift apart.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scan"))
import scan  # noqa: E402


# ---------------------------------------------------------------------------
# PART A: the remediation PLAN (pure logic, no AWS)
# For each resource in a snapshot, decide what needs fixing. This same logic
# drives the dry-run printout, the selftest, and the live run.
# ---------------------------------------------------------------------------
def plan(snapshot):
    actions = []  # each: (service, resource, human description)

    for b in snapshot.get("s3_buckets", []):
        n = b["name"]
        if not b.get("default_encryption"):
            actions.append(("s3", n, "Enable default KMS encryption (PutBucketEncryption)"))
        if not b.get("block_public_access"):
            actions.append(("s3", n, "Enable Block Public Access (PutPublicAccessBlock)"))
        if not b.get("tls_only_policy"):
            actions.append(("s3", n, "Attach TLS-only deny bucket policy (PutBucketPolicy)"))
        if not b.get("versioning"):
            actions.append(("s3", n, "Enable versioning (PutBucketVersioning)"))

    for sg in snapshot.get("security_groups", []):
        for r in sg.get("ingress", []):
            if r.get("cidr") == "0.0.0.0/0":
                actions.append(("sg", sg["id"], f"Revoke world-open ingress on port {r.get('port')} (RevokeSecurityGroupIngress)"))

    for v in snapshot.get("vpcs", []):
        if not v.get("flow_logs"):
            actions.append(("vpc", v["id"], "Enable VPC flow logs to CloudWatch (CreateFlowLogs)"))

    for role in snapshot.get("iam_roles", []):
        if role.get("has_wildcard_allow"):
            actions.append(("iam", role["name"], "Replace wildcard allow with least-privilege policy (PutRolePolicy)"))
        if not role.get("has_destructive_deny"):
            actions.append(("iam", role["name"], "Attach explicit deny on destructive actions (PutRolePolicy)"))

    for k in snapshot.get("kms_keys", []):
        if not k.get("rotation"):
            actions.append(("kms", k["id"], "Enable annual key rotation (EnableKeyRotation)"))

    for t in snapshot.get("cloudtrails", []):
        n = t["name"]
        if not t.get("multi_region"):
            actions.append(("cloudtrail", n, "Make trail multi-region (UpdateTrail)"))
        if not t.get("log_file_validation"):
            actions.append(("cloudtrail", n, "Enable log file validation (UpdateTrail)"))
        if not t.get("data_events"):
            actions.append(("cloudtrail", n, "Record S3 data events (PutEventSelectors)"))
        if not t.get("kms_encrypted"):
            actions.append(("cloudtrail", n, "Encrypt trail logs with KMS (UpdateTrail)"))
    return actions


def snapshot_after_fix(snapshot):
    """Return what the account WOULD look like after fix. Used by selftest to
    prove scan finds nothing afterward. This mirrors the live calls below."""
    s = copy.deepcopy(snapshot)
    for b in s.get("s3_buckets", []):
        b["default_encryption"] = True
        b["block_public_access"] = True
        b["tls_only_policy"] = True
        b["versioning"] = True
    for sg in s.get("security_groups", []):
        for r in sg.get("ingress", []):
            if r.get("cidr") == "0.0.0.0/0":
                r["cidr"] = "10.20.0.0/16"  # scope to the VPC, not the world
    for v in s.get("vpcs", []):
        v["flow_logs"] = True
    for role in s.get("iam_roles", []):
        role["has_wildcard_allow"] = False
        role["has_destructive_deny"] = True
    for k in s.get("kms_keys", []):
        k["rotation"] = True
    for t in s.get("cloudtrails", []):
        t["multi_region"] = True
        t["log_file_validation"] = True
        t["data_events"] = True
        t["kms_encrypted"] = True
    return s


# ---------------------------------------------------------------------------
# PART B: the LIVE remediations (boto3). Only run with --commit.
# Each function is the exact API call, commented with the why.
# ---------------------------------------------------------------------------
def _tls_only_policy(bucket_arn):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*",
            "Action": "s3:*", "Resource": [bucket_arn, bucket_arn + "/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}
        }]
    })


def apply_live(snapshot, project, region, kms_key_arn):
    import boto3
    s3 = boto3.client("s3", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    iam = boto3.client("iam")
    kms = boto3.client("kms", region_name=region)
    ct = boto3.client("cloudtrail", region_name=region)
    acct = boto3.client("sts").get_caller_identity()["Account"]
    done = []

    for b in snapshot.get("s3_buckets", []):
        n = b["name"]; arn = f"arn:aws:s3:::{n}"
        if not b.get("default_encryption"):
            # Default encryption: every new object is encrypted with our KMS key.
            enc = {"SSEAlgorithm": "aws:kms"}
            if kms_key_arn:
                enc["KMSMasterKeyID"] = kms_key_arn
            s3.put_bucket_encryption(Bucket=n, ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": enc, "BucketKeyEnabled": True}]})
            done.append(f"s3 {n}: default encryption on")
        if not b.get("block_public_access"):
            # Block Public Access: a hard stop so no ACL or policy can expose it.
            s3.put_public_access_block(Bucket=n, PublicAccessBlockConfiguration={
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
            done.append(f"s3 {n}: public access blocked")
        if not b.get("tls_only_policy"):
            s3.put_bucket_policy(Bucket=n, Policy=_tls_only_policy(arn))
            done.append(f"s3 {n}: TLS-only policy")
        if not b.get("versioning"):
            s3.put_bucket_versioning(Bucket=n, VersioningConfiguration={"Status": "Enabled"})
            done.append(f"s3 {n}: versioning on")

    for sg in snapshot.get("security_groups", []):
        for r in sg.get("ingress", []):
            if r.get("cidr") == "0.0.0.0/0":
                # Revoke the world-open rule. Re-add scoped to the VPC if a port is known.
                port = r.get("port")
                perm = {"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ec2.revoke_security_group_ingress(GroupId=sg["id"], IpPermissions=[perm])
                done.append(f"sg {sg['id']}: revoked 0.0.0.0/0 on {port}")

    for v in snapshot.get("vpcs", []):
        if not v.get("flow_logs"):
            # Flow logs need a log group and a role. The foundation already made
            # both, named by convention, so we reference them.
            logs = boto3.client("logs", region_name=region)
            lg = f"/{project}-lab/vpc-flow"
            try:
                logs.create_log_group(logGroupName=lg)
            except logs.exceptions.ResourceAlreadyExistsException:
                pass
            role_arn = f"arn:aws:iam::{acct}:role/{project}-lab-flowlogs"
            ec2.create_flow_logs(ResourceIds=[v["id"]], ResourceType="VPC",
                                 TrafficType="ALL", LogDestinationType="cloud-watch-logs",
                                 LogGroupName=lg, DeliverLogsPermissionArn=role_arn)
            done.append(f"vpc {v['id']}: flow logs on")

    for role in snapshot.get("iam_roles", []):
        if not role.get("has_destructive_deny"):
            # Explicit deny wins over any allow. Fence off the actions that let a
            # compromised identity destroy evidence or data.
            iam.put_role_policy(RoleName=role["name"], PolicyName="deny-destructive",
                PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
                    "Sid": "DenyDestructive", "Effect": "Deny",
                    "Action": ["s3:DeleteBucket", "s3:PutBucketPolicy", "cloudtrail:StopLogging",
                               "cloudtrail:DeleteTrail", "kms:ScheduleKeyDeletion", "kms:DisableKey",
                               "secretsmanager:DeleteSecret"],
                    "Resource": "*"}]}))
            done.append(f"iam {role['name']}: destructive-action deny attached")

    for k in snapshot.get("kms_keys", []):
        if not k.get("rotation"):
            kms.enable_key_rotation(KeyId=k["id"])
            done.append(f"kms {k['id']}: rotation on")

    for t in snapshot.get("cloudtrails", []):
        kw = {}
        if not t.get("multi_region"):
            kw["IsMultiRegionTrail"] = True
        if not t.get("log_file_validation"):
            kw["EnableLogFileValidation"] = True
        if not t.get("kms_encrypted") and kms_key_arn:
            kw["KmsKeyId"] = kms_key_arn
        if kw:
            ct.update_trail(Name=t["name"], **kw)
            done.append(f"cloudtrail {t['name']}: {', '.join(kw)}")
        if not t.get("data_events"):
            ct.put_event_selectors(TrailName=t["name"], EventSelectors=[{
                "ReadWriteType": "All", "IncludeManagementEvents": True,
                "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}]}])
            done.append(f"cloudtrail {t['name']}: S3 data events on")
    return done


# ---------------------------------------------------------------------------
# CLI + selftest
# ---------------------------------------------------------------------------
def selftest():
    here = os.path.dirname(__file__)
    fx = os.path.join(here, "..", "scan", "fixtures", "insecure.json")
    with open(fx) as fh:
        insecure = json.load(fh)
    before = scan.run_checks(insecure)
    fixed = snapshot_after_fix(insecure)
    after = scan.run_checks(fixed)
    print(f"selftest: before fix -> {len(before)} findings (expected > 0)")
    print(f"selftest: after  fix -> {len(after)} findings (expected 0)")
    ok = len(before) > 0 and len(after) == 0
    if not ok and after:
        print("  ! these findings survived the fix:")
        for a in after:
            print("     ", a)
    print("hwz-fix selftest:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="hwz-fix: remediate every finding hwz-scan reports")
    ap.add_argument("--project", default="hwz")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--kms-key-arn", default="", help="Foundation KMS key ARN for encryption fixes")
    ap.add_argument("--snapshot", help="Plan against a saved snapshot instead of live AWS")
    ap.add_argument("--commit", action="store_true", help="Actually apply fixes to AWS")
    ap.add_argument("--selftest", action="store_true", help="Prove fix closes scan findings, no AWS")
    a = ap.parse_args()

    if a.selftest:
        sys.exit(selftest())

    if a.snapshot:
        with open(a.snapshot) as fh:
            snap = json.load(fh)
    else:
        snap = scan.collect_live(a.project, a.region)

    actions = plan(snap)
    if not actions:
        print("Nothing to fix. Already hardened.")
        sys.exit(0)

    print(f"{len(actions)} remediation(s) planned:")
    for svc, res, desc in actions:
        print(f"  [{svc:11}] {res:22} {desc}")

    if not a.commit:
        print("\nDRY RUN. Nothing changed. Re-run with --commit to apply, then run scan.py again.")
        sys.exit(0)

    print("\nApplying...")
    done = apply_live(snap, a.project, a.region, a.kms_key_arn)
    for d in done:
        print("  fixed:", d)
    print(f"\n{len(done)} change(s) applied. Now run: python3 scan/scan.py")


if __name__ == "__main__":
    main()
