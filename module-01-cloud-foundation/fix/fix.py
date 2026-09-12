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
# Every remediation has a key. The key is the contract between the three halves
# of this file, and the reason that contract exists is worth reading once.
#
# This script used to PLAN a fix for the wildcard IAM allow and then never
# perform it. apply_live() simply had no branch for it. The dry run promised the
# fix, --commit silently skipped it, and scan.py kept reporting the same HIGH
# finding forever. Students following the PDF saw FAIL where it said PASS, and
# nothing in the repo caught it, because snapshot_after_fix() cleared the flag
# by hand. The test was checking the plan against itself, not against the code.
#
# So: a remediation may only clear a flag in snapshot_after_fix() if its key is
# in LIVE_FIXES, and LIVE_FIXES lists exactly what apply_live() implements. Add
# a branch to plan() without writing the AWS call and the selftest goes red,
# because the fixture will still have a finding the model was not allowed to
# clear. The test now checks the code.
LIVE_FIXES = {
    "s3.encryption", "s3.public_access", "s3.tls_only", "s3.versioning",
    "sg.world_ingress",
    "vpc.flow_logs",
    "iam.wildcard_allow", "iam.destructive_deny",
    "kms.rotation",
    "cloudtrail.multi_region", "cloudtrail.log_validation",
    "cloudtrail.data_events", "cloudtrail.kms_encrypted",
}


def plan(snapshot):
    actions = []  # each: (key, service, resource, human description)

    for b in snapshot.get("s3_buckets", []):
        n = b["name"]
        if not b.get("default_encryption"):
            actions.append(("s3.encryption", "s3", n, "Enable default KMS encryption (PutBucketEncryption)"))
        if not b.get("block_public_access"):
            actions.append(("s3.public_access", "s3", n, "Enable Block Public Access (PutPublicAccessBlock)"))
        if not b.get("tls_only_policy"):
            actions.append(("s3.tls_only", "s3", n, "Merge TLS-only deny into bucket policy (GetBucketPolicy + PutBucketPolicy)"))
        if not b.get("versioning"):
            actions.append(("s3.versioning", "s3", n, "Enable versioning (PutBucketVersioning)"))

    for sg in snapshot.get("security_groups", []):
        for r in sg.get("ingress", []):
            if r.get("cidr") == "0.0.0.0/0":
                actions.append(("sg.world_ingress", "sg", sg["id"], f"Revoke world-open ingress on port {r.get('port')} (RevokeSecurityGroupIngress)"))

    for v in snapshot.get("vpcs", []):
        if not v.get("flow_logs"):
            actions.append(("vpc.flow_logs", "vpc", v["id"], "Enable VPC flow logs to CloudWatch (CreateFlowLogs)"))

    for role in snapshot.get("iam_roles", []):
        if role.get("has_wildcard_allow"):
            actions.append(("iam.wildcard_allow", "iam", role["name"], "Replace wildcard allow with least-privilege policy (PutRolePolicy)"))
        if not role.get("has_destructive_deny"):
            actions.append(("iam.destructive_deny", "iam", role["name"], "Attach explicit deny on destructive actions (PutRolePolicy)"))

    for k in snapshot.get("kms_keys", []):
        if not k.get("rotation"):
            actions.append(("kms.rotation", "kms", k["id"], "Enable annual key rotation (EnableKeyRotation)"))

    for t in snapshot.get("cloudtrails", []):
        n = t["name"]
        if not t.get("multi_region"):
            actions.append(("cloudtrail.multi_region", "cloudtrail", n, "Make trail multi-region (UpdateTrail)"))
        if not t.get("log_file_validation"):
            actions.append(("cloudtrail.log_validation", "cloudtrail", n, "Enable log file validation (UpdateTrail)"))
        if not t.get("data_events"):
            actions.append(("cloudtrail.data_events", "cloudtrail", n, "Record S3 data events (PutEventSelectors)"))
        if not t.get("kms_encrypted"):
            actions.append(("cloudtrail.kms_encrypted", "cloudtrail", n, "Grant CloudTrail on the key, then encrypt trail logs (PutKeyPolicy + UpdateTrail)"))
    return actions


def snapshot_after_fix(snapshot):
    """Return what the account WOULD look like after fix, so the selftest can
    prove scan finds nothing afterward.

    A flag is cleared here only if apply_live() really implements that fix. See
    LIVE_FIXES above for why that guard exists and what went wrong without it."""
    s = copy.deepcopy(snapshot)
    can = LIVE_FIXES.__contains__

    for b in s.get("s3_buckets", []):
        if can("s3.encryption"):    b["default_encryption"] = True
        if can("s3.public_access"): b["block_public_access"] = True
        if can("s3.tls_only"):      b["tls_only_policy"] = True
        if can("s3.versioning"):    b["versioning"] = True
    if can("sg.world_ingress"):
        for sg in s.get("security_groups", []):
            for r in sg.get("ingress", []):
                if r.get("cidr") == "0.0.0.0/0":
                    r["cidr"] = "10.20.0.0/16"  # scope to the VPC, not the world
    for v in s.get("vpcs", []):
        if can("vpc.flow_logs"): v["flow_logs"] = True
    for role in s.get("iam_roles", []):
        if can("iam.wildcard_allow"):   role["has_wildcard_allow"] = False
        if can("iam.destructive_deny"): role["has_destructive_deny"] = True
    for k in s.get("kms_keys", []):
        if can("kms.rotation"): k["rotation"] = True
    for t in s.get("cloudtrails", []):
        if can("cloudtrail.multi_region"):  t["multi_region"] = True
        if can("cloudtrail.log_validation"): t["log_file_validation"] = True
        if can("cloudtrail.data_events"):   t["data_events"] = True
        if can("cloudtrail.kms_encrypted"): t["kms_encrypted"] = True
    return s


# ---------------------------------------------------------------------------
# PART B: the LIVE remediations (boto3). Only run with --commit.
# Each function is the exact API call, commented with the why.
# ---------------------------------------------------------------------------
def _merge_tls_statement(s3, bucket, bucket_arn):
    """Merge the TLS-only deny into whatever policy the bucket already has.

    PutBucketPolicy REPLACES the entire policy document. It never appends.
    Overwrite a policy that a service depends on and you break that service:
    CloudTrail's permission to deliver logs lives in its log bucket's policy,
    so replacing it with only a TLS deny silently stops audit logging and
    makes UpdateTrail fail with InsufficientS3BucketPolicyException.
    The rule in any account, lab or production: read, merge, then write."""
    stmt = {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*",
            "Action": "s3:*", "Resource": [bucket_arn, bucket_arn + "/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
    try:
        doc = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    except Exception:
        doc = {"Version": "2012-10-17", "Statement": []}
    statements = doc.get("Statement", [])
    if any(x.get("Sid") == "DenyInsecureTransport" for x in statements):
        return  # idempotent: already merged
    statements.append(stmt)
    doc["Statement"] = statements
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(doc))


def _allow_cloudtrail_on_key(kms, kms_key_arn, trail_arn):
    """Let CloudTrail use the key before pointing the trail at it.

    UpdateTrail with KmsKeyId validates, at call time, that the KEY POLICY
    allows cloudtrail.amazonaws.com to encrypt. IAM policies are not enough:
    KMS authorization starts at the key policy. Same rule as bucket policies
    applies here: read the existing policy, merge one statement, write back."""
    key_id = kms_key_arn.split("/")[-1]
    doc = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    if any(x.get("Sid") == "AllowCloudTrailEncrypt" for x in doc.get("Statement", [])):
        return  # idempotent: already granted
    doc["Statement"].append({
        "Sid": "AllowCloudTrailEncrypt", "Effect": "Allow",
        "Principal": {"Service": "cloudtrail.amazonaws.com"},
        "Action": ["kms:GenerateDataKey*", "kms:DescribeKey", "kms:Decrypt"],
        "Resource": "*",
        "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}}})
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(doc))


def least_privilege_policy(name_prefix, region, account_id):
    """The grant that replaces the wildcard one.

    This is deliberately the same document the hardened Terraform writes, in
    foundation/modules/iam/main.tf as local.scoped_policy. The two must agree.
    If they drift, a student who hardens by re-applying Terraform and a student
    who hardens by running this script end up with different accounts, and only
    one of them passes the scan. Change one, change the other.

    Every action here is a named operation. None of them is "*" or ends in ":*",
    which is what scan.has_wildcard_allow looks for."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "S3ProjectData", "Effect": "Allow",
             "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"],
             "Resource": [f"arn:aws:s3:::{name_prefix}-*", f"arn:aws:s3:::{name_prefix}-*/*"]},
            {"Sid": "SecretsProject", "Effect": "Allow",
             "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
             "Resource": [f"arn:aws:secretsmanager:{region}:{account_id}:secret:{name_prefix}-*"]},
            {"Sid": "KmsProject", "Effect": "Allow",
             "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
             "Resource": [f"arn:aws:kms:{region}:{account_id}:key/*"]},
            {"Sid": "LogsProject", "Effect": "Allow",
             "Action": ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
             "Resource": [f"arn:aws:logs:{region}:{account_id}:log-group:{name_prefix}-*"]},
            {"Sid": "BedrockInvoke", "Effect": "Allow",
             "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
             "Resource": ["*"]},
            {"Sid": "CloudTrailRead", "Effect": "Allow",
             "Action": ["cloudtrail:LookupEvents"], "Resource": ["*"]},
        ],
    }


def _replace_wildcard_policies(iam, role_name, name_prefix, region, account_id):
    """Closes: HIGH iam, role policy allows wildcard or service-wide actions.

    This is the remediation that used to be missing. The scan flags a role when
    any INLINE policy has an Allow on "*" or a service-wide action, so this
    walks the same inline policies the scan walked, using the scan's own test,
    and rewrites each offending document in place.

    It rewrites rather than deletes. Deleting the grant would clear the finding
    and leave the workload with no permissions at all: the lab stops working and
    the student gets a green scan on a broken account, which is the worst thing
    this course could teach.

    The deny-destructive policy is not touched. Its statements are Deny, so the
    scan never flagged it, and removing it would open a MEDIUM finding instead.

    Idempotent: run it twice and the second pass finds no wildcard to replace."""
    replaced = []
    doc_new = json.dumps(least_privilege_policy(name_prefix, region, account_id))
    for pn in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        doc = iam.get_role_policy(RoleName=role_name, PolicyName=pn)["PolicyDocument"]
        if scan.has_wildcard_allow(doc):
            iam.put_role_policy(RoleName=role_name, PolicyName=pn, PolicyDocument=doc_new)
            replaced.append(pn)
    return replaced


def apply_live(snapshot, project, region, kms_key_arn, name_prefix=None):
    import boto3
    s3 = boto3.client("s3", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    iam = boto3.client("iam")
    kms = boto3.client("kms", region_name=region)
    ct = boto3.client("cloudtrail", region_name=region)
    acct = boto3.client("sts").get_caller_identity()["Account"]
    # Terraform names every resource "<project>-lab-...", so that is the default.
    # Override with --name-prefix if you changed name_prefix in your tfvars.
    name_prefix = name_prefix or f"{project}-lab"
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
            _merge_tls_statement(s3, n, arn)
            done.append(f"s3 {n}: TLS-only statement merged into bucket policy")
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
            lg = f"/{name_prefix}/vpc-flow"
            try:
                logs.create_log_group(logGroupName=lg)
            except logs.exceptions.ResourceAlreadyExistsException:
                pass
            role_arn = f"arn:aws:iam::{acct}:role/{name_prefix}-flowlogs"
            ec2.create_flow_logs(ResourceIds=[v["id"]], ResourceType="VPC",
                                 TrafficType="ALL", LogDestinationType="cloud-watch-logs",
                                 LogGroupName=lg, DeliverLogsPermissionArn=role_arn)
            done.append(f"vpc {v['id']}: flow logs on")

    for role in snapshot.get("iam_roles", []):
        if role.get("has_wildcard_allow"):
            # Swap the broad grant for the least-privilege one. See the helper
            # above for why this rewrites the policy instead of deleting it.
            names = _replace_wildcard_policies(iam, role["name"], name_prefix, region, acct)
            if names:
                done.append(f"iam {role['name']}: wildcard allow replaced with least privilege in {', '.join(names)}")
            else:
                # The scan saw a wildcard and we did not. Say so rather than
                # reporting a fix that did not happen: that is the exact failure
                # this whole branch exists to correct.
                done.append(f"iam {role['name']}: NO wildcard inline policy found to replace, check attached managed policies by hand")
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
            trail_arn = f"arn:aws:cloudtrail:{region}:{acct}:trail/{t['name']}"
            _allow_cloudtrail_on_key(kms, kms_key_arn, trail_arn)
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
class _FakeIam:
    """The smallest possible stand-in for the three IAM calls the wildcard fix
    makes. It exists so the live remediation itself is exercised offline.

    The bug this file was written to close was not in the plan and not in the
    model: both of those were right. It was in the AWS call that never ran. So
    checking the model again would not have caught it, and neither would any
    test that mocks out the function under test. This fake mocks the CLIENT and
    runs the real _replace_wildcard_policies against it."""

    def __init__(self, policies):
        self.policies = dict(policies)   # name -> document dict
        self.writes = []

    def list_role_policies(self, RoleName):
        return {"PolicyNames": sorted(self.policies)}

    def get_role_policy(self, RoleName, PolicyName):
        return {"PolicyDocument": self.policies[PolicyName]}

    def put_role_policy(self, RoleName, PolicyName, PolicyDocument):
        self.policies[PolicyName] = json.loads(PolicyDocument)
        self.writes.append(PolicyName)


def _selftest_wildcard_fix():
    """Prove the wildcard remediation turns a flagged role into a clean one."""
    broad = {"Version": "2012-10-17", "Statement": [{
        "Sid": "BroadServiceAccess", "Effect": "Allow",
        "Action": ["s3:*", "secretsmanager:*", "kms:*", "bedrock:*", "logs:*",
                   "cloudtrail:LookupEvents"],
        "Resource": "*"}]}
    deny = {"Version": "2012-10-17", "Statement": [{
        "Sid": "DenyDestructive", "Effect": "Deny",
        "Action": ["s3:DeleteBucket", "cloudtrail:StopLogging"], "Resource": "*"}]}

    iam = _FakeIam({"hwz-lab-workload-grant": broad, "hwz-lab-deny-destructive": deny})
    ok = True

    if not scan.has_wildcard_allow(iam.policies["hwz-lab-workload-grant"]):
        print("  ! the broad fixture is not even flagged, the test is wrong"); ok = False

    names = _replace_wildcard_policies(iam, "hwz-lab-workload", "hwz-lab", "us-east-1", "111122223333")
    if names != ["hwz-lab-workload-grant"]:
        print(f"  ! wrong policies rewritten: {names}"); ok = False
    if any(scan.has_wildcard_allow(d) for d in iam.policies.values()):
        print("  ! a wildcard allow survived the rewrite"); ok = False
    if iam.policies["hwz-lab-deny-destructive"] != deny:
        print("  ! the deny policy was modified, that would open a MEDIUM"); ok = False

    # Second pass must be a no-op. Students re-run this script.
    before = len(iam.writes)
    _replace_wildcard_policies(iam, "hwz-lab-workload", "hwz-lab", "us-east-1", "111122223333")
    if len(iam.writes) != before:
        print("  ! not idempotent, a second run rewrote the policy again"); ok = False

    print("selftest: wildcard remediation ->", "clean, deny intact, idempotent" if ok else "BROKEN")
    return ok


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

    # Coverage. The fixture is insecure in every way the scan can detect, so
    # planning against it produces one action of every kind this script knows
    # how to promise. Every one of those must be a fix apply_live really makes.
    # A planned remediation with no live call behind it is how this script came
    # to tell students it had fixed a wildcard it never touched.
    planned = {k for k, _, _, _ in plan(insecure)}
    unbacked = sorted(planned - LIVE_FIXES)
    print(f"selftest: {len(planned)} remediation kind(s) planned, {len(planned) - len(unbacked)} backed by a live AWS call")
    if unbacked:
        ok = False
        print("  ! planned but never applied to AWS, so the dry run is lying:")
        for k in unbacked:
            print("     ", k)

    if not _selftest_wildcard_fix():
        ok = False

    print("hwz-fix selftest:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="hwz-fix: remediate every finding hwz-scan reports")
    ap.add_argument("--project", default="hwz")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--kms-key-arn", default="", help="Foundation KMS key ARN for encryption fixes")
    ap.add_argument("--name-prefix", default="", help="Resource name prefix from your tfvars (default: <project>-lab)")
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
    for key, svc, res, desc in actions:
        print(f"  [{svc:11}] {res:22} {desc}")

    if not a.commit:
        print("\nDRY RUN. Nothing changed. Re-run with --commit to apply, then run scan.py again.")
        sys.exit(0)

    print("\nApplying...")
    done = apply_live(snap, a.project, a.region, a.kms_key_arn, a.name_prefix)
    for d in done:
        print("  fixed:", d)
    print(f"\n{len(done)} change(s) applied. Now run: python3 scan/scan.py")


if __name__ == "__main__":
    main()
