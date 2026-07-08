# The hardening pass, control by control

You deployed the weak stack. Now you read the diff and close every hole. Run `terraform plan -var-file=hardened.tfvars` and keep it open next to this file. Every change below is one flag in `hardened.tfvars` and the resource it drives.

The rule that makes this work: nothing here is a new file you had to remember to write. The weak stack and the hardened stack are the same code. The weakness was a value, not a missing resource. That is what makes it safe to teach and safe to run.

## 1. Network: close the endpoint and turn the lights on

Flags: `ssh_ingress_cidr`, `vpc_flow_logs`

Baseline let the whole internet reach the interface-endpoint security group on 443, and captured no network telemetry at all. Hardened sets the ingress CIDR to the VPC block `10.20.0.0/16` so only traffic already inside the VPC can reach the endpoints, and turns on VPC flow logs into the CloudWatch group the observability module owns.

Why it matters: an open endpoint SG is a lateral-movement gift, and with no flow logs you cannot answer the one question every incident starts with, which is what talked to what. You cannot investigate traffic you never recorded.

## 2. KMS: scope the key and let CloudTrail use it

Flags: `kms_strict_key_policy`, `kms_allow_cloudtrail`

Baseline used the classic wide-open key policy where the account root can do anything and no service is granted use. Hardened splits it: root keeps administration, the workload role gets encrypt and decrypt only, key rotation turns on, and a CloudTrail service statement is added so the trail can encrypt its logs with this key.

Why it matters: a key everyone can use is not a control, it is decoration. And this is the exact grant the old course was missing. Turning on trail encryption without granting CloudTrail on the key is what made the old stack fail. Here the grant and the encryption flip on together, on purpose, so you see the dependency instead of tripping over it.

## 3. IAM: stop pretending you will tighten it later

Flag: `iam_deny_destructive`

Baseline gave the workload role a broad allow across S3, KMS, Secrets Manager, and Bedrock. That is the give-it-admin-so-it-stops-erroring pattern, and the tightening never happens. Hardened bolts an explicit deny on top for the actions that let a compromised app erase your evidence and your data: delete the bucket, rewrite the bucket policy, stop or delete the trail, schedule the key for deletion, delete the secret.

Why it matters: explicit deny always wins over any allow. This is the pattern that survives a real audit, because it does not depend on you having scoped every allow perfectly. It fences off the actions you never want an app identity to take, full stop.

## 4. S3 data bucket: encrypt, block, enforce, version

Flags: `s3_default_encryption`, `s3_block_public_access`, `s3_enforce_tls`, `s3_versioning`

Baseline stored objects in the clear, allowed the bucket to be made public, accepted plaintext HTTP requests, and kept no version history. Hardened turns on default KMS encryption using the foundation key, attaches a Block Public Access configuration, adds a bucket policy that denies any request where `aws:SecureTransport` is false, and enables versioning.

Why it matters: this is the single most common cloud breach headline, an open unencrypted bucket. Test three in the old course nearly broke people because default encryption was off and nothing tripped in CloudTrail. Here you watch each of the four controls land as a separate line in the plan, so you know what each one actually does instead of copying a block that does all four invisibly.

## 5. CloudTrail: make the trail worth having

Flags: `cloudtrail_multi_region`, `cloudtrail_log_file_validation`, `cloudtrail_data_events`, `cloudtrail_use_kms`

Baseline ran a single-region trail with no log-file validation, no data events, and no encryption. It technically logged, which is the trap, because it gives you the comfort of a trail without the evidence you need. Hardened makes it multi-region, turns on log-file (digest) validation so tampering is detectable, adds an S3 object-level data-event selector so reads and writes of objects are recorded, and encrypts the logs with the foundation KMS key.

Why it matters: a trail that does not record data events will not show you the attacker reading your bucket. A trail without digest validation can be edited after the fact and you will never know. The trail and its log bucket live in the same module with the correct two-statement bucket policy and a `depends_on`, which is the piece the old course got wrong and the reason the trail would not create.

## What to check when you are done

Re-run whatever scanner you use, or walk the console. The findings that were there on the baseline stack are gone. Then read the hardened plan output one more time and make sure you can say, in one sentence each, what every changed line defends against. If you can teach it back, you own it.

Then tear it down.

---

Build it. Release it. Break it. Harden it.

By Zach Marcy. Cybersecurity Architect and Mentor. 20+ years in IT, 6 in cybersecurity. I design and secure cloud environments that deploy and secure APIs and AI.

Cybersecurity Education That Gets You Hired, Promoted and Paid.

© 2026 Vigilantia Technologies INC. All rights reserved. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
