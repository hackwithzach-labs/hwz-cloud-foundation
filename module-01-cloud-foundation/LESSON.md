# The four-step lab, explained

Every project and pillar in this program runs the same four steps. You never just get handed a secure system. You build the insecure one, prove it is insecure, fix it, and prove the fix worked, using scripts you can read and run as many times as you want. This document explains the code behind each step so you understand what you are running and why, not just that it works.

The four steps, always in this order:

1. Deploy the insecure stack, and understand why each piece is insecure.
2. Scan it with `scan/scan.py` to identify the insecure structure.
3. Fix it with `fix/fix.py` to remediate every finding.
4. Run the exact same scan again and watch every check pass.

Then tear it down.

## Step 1: the insecure deployment, and why it is insecure

The deployment is Terraform, in `foundation/`. It applies cleanly on the first try, and it is wide open on purpose. The weaknesses are values, not missing pieces, so you can see and change each one. Here is what is weak and why it matters, module by module.

The S3 data bucket (`modules/s3`) has no default encryption, so objects are stored in the clear and a stolen copy is immediately readable. It has no Block Public Access, so a single careless ACL or policy can expose it to the internet. It accepts plaintext requests, because there is no policy denying non-TLS traffic. And it has no versioning, so an overwrite or delete is permanent. Those four are the classic storage-breach set.

The IAM workload role (`modules/iam`) carries a broad allow across S3, KMS, and Secrets Manager. That is the give-it-admin-so-it-stops-erroring pattern, and it is the multiplier that turns one compromised identity into a full-account compromise. There is no explicit deny, so nothing stops that identity from deleting your evidence.

The endpoint security group (`modules/vpc`) allows inbound from `0.0.0.0/0`, the whole internet, and VPC flow logs are off, so you have no record of network traffic to investigate. The KMS key (`modules/kms`) has rotation disabled. And CloudTrail (`modules/cloudtrail`) is single-region, has no log file validation, records no S3 data events, and is not encrypted, which is the trap of a trail that runs but records nothing worth having.

Every one of those maps to an attacker technique you studied. Read `HARDEN.md` for the control-by-control mapping. The point of Step 1 is that you can point at each weakness and say what it lets an attacker do.

## Step 2: how the scan script works

`scan/scan.py` is the tool that proves the stack insecure. Its design is the important lesson: it separates reading AWS from judging what it read.

`collect_live()` uses the AWS SDK, boto3, to walk your account and turn it into a plain Python dictionary, a snapshot. It only looks at resources tagged with your project, so it never touches anything outside your lab. `run_checks()` takes that snapshot and runs a list of small check functions, one per control: is the bucket encrypted, is public access blocked, is the security group open to the world, is the trail multi-region, and so on. Each failed check becomes a finding with a severity and a one-line explanation of the risk.

Why split it this way? Because it means the checks can be tested with no AWS at all. Run `python3 scan/scan.py --selftest` and it runs the checks against a known-insecure and a known-secure fixture and confirms the first fails and the second passes. That is how you trust a scanner: you prove its logic before you point it at anything real. When you run it live, the flow is the same, collect then check then report, and a non-zero exit code means it found problems.

## Step 3: how the fix script works

`fix/fix.py` is the remediation tool, and it is built to pair exactly with the scanner. It imports the scanner's own checks so the two can never drift apart.

It has three parts. `plan()` takes a snapshot and decides what needs fixing, producing a list of named actions, each one saying which API call it will make. `apply_live()` makes those calls with boto3: `put_bucket_encryption` to turn on default encryption, `put_public_access_block` to lock down public access, a merge of the TLS-only deny into the existing bucket policy, `revoke_security_group_ingress` to close the world-open rule, `enable_key_rotation` on the key, `update_trail` and `put_event_selectors` to make the trail useful, and `put_role_policy` to attach the explicit deny on destructive actions. Every call is a small function with a comment explaining why the fix works.

Two of those calls carry lessons that go far beyond this lab. First, `PutBucketPolicy` replaces the entire policy document. It never appends. CloudTrail's permission to deliver logs lives in its log bucket's policy, so overwriting that policy with only a TLS deny silently kills audit logging and makes later `UpdateTrail` calls fail with `InsufficientS3BucketPolicyException`. The script therefore reads the existing policy, merges one statement in, and writes the result back. Read, merge, write: that is the rule for any shared policy document, in any account. Second, pointing a trail at a KMS key requires the KEY POLICY to allow `cloudtrail.amazonaws.com`. IAM policies are not enough, because KMS authorization starts at the key policy. The script merges that grant into the key policy before it calls `update_trail`.

Two safety properties matter. It defaults to a dry run that prints the plan and changes nothing, so you always see what it will do before it does it. And it is idempotent, so running it twice is safe: both merges check for their statement Sid before writing. The `--commit` flag is what actually writes to AWS, and you only use it in your sandbox.

And here is the proof that the fix is correct, which you can run with no AWS: `python3 fix/fix.py --selftest` takes the insecure fixture, applies the fix logic, then runs the scanner's checks on the result and asserts zero findings remain. If the fix ever failed to close something the scanner flags, the selftest would fail. That is how we know, before you run anything live, that Step 3 closes exactly what Step 2 opens.

## Step 4: prove it, with the same scanner

Step 4 is not a new tool. It is Step 2 again. You run `python3 scan/scan.py` a second time, against the same account, and it reports clean with a zero exit code. Same scanner, same account, opposite result. The difference between the Step 2 run and the Step 4 run is the entire security lesson, made real and repeatable.

## The relationship to Terraform hardening

You will notice `foundation/hardened.tfvars` also exists. That is the infrastructure-as-code way to make the same fixes permanent: flip the flags and re-apply, and the secure state lives in version control. The fix script is the operational way: what an engineer runs against a live account to remediate right now, reading and understanding every call. This program teaches both, because in the real job you do both. You remediate live under pressure, then you codify the fix so it never regresses.

## Run it

The exact commands are in `RUNBOOK.md`. The short version:

```bash
cd foundation && terraform apply -var-file=baseline.tfvars   # 1. deploy insecure
cd .. && python3 scan/scan.py                                # 2. scan: FAIL
python3 fix/fix.py --commit --kms-key-arn <foundation key>   # 3. fix
python3 scan/scan.py                                         # 4. scan: PASS
cd foundation && terraform destroy -var-file=baseline.tfvars # tear down
```

Read the scripts before you run them. They are short, they are commented, and understanding them is the point.

---

Build it. Release it. Break it. Harden it.

© 2026 Vigilantia Technologies INC. All rights reserved. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
