# Runbook: the four-step lab on real AWS

This is the loop every project and pillar in the program runs on. You deploy the
insecure stack, scan it to prove it insecure, fix it with a script, then run the
same scan again and watch it pass. Same four steps everywhere. `LESSON.md`
explains the code behind each step. Do it once here and you know the machinery.

Use an ISOLATED SANDBOX AWS account. Not production. Not your employer's.

## 0. One-time setup

```bash
# clone your own copy (this repo) and point the AWS CLI at your sandbox
aws sts get-caller-identity          # confirm you are in the sandbox account
python3 -m venv .venv && source .venv/bin/activate
pip install -r scan/requirements.txt
```

## 1. Build and release the WEAK stack

```bash
cd foundation
terraform init
terraform apply -var-file=baseline.tfvars -auto-approve
cd ..
```

It applies clean. That is the bar. Nothing missing, nothing broken, just wide open.

## 2. Prove it is insecure

```bash
python3 scan/scan.py --project hwz --region us-east-1
```

Expect a FAIL with roughly a dozen findings and a non-zero exit code. Read every
one. Open the console and confirm the finding is real. This is the break step:
you are attacking your own build by looking at it the way an auditor would.

## 3. Fix it with the remediation script

```bash
# get the foundation KMS key ARN for the encryption fixes
KEY=$(cd foundation && terraform output -raw kms_key_arn)

python3 fix/fix.py --project hwz --region us-east-1                      # dry run: see the plan
python3 fix/fix.py --project hwz --region us-east-1 --kms-key-arn "$KEY" --commit
```

The dry run prints every remediation and the exact AWS API call it makes, and
changes nothing. Read it. Then `--commit` applies the fixes. It is idempotent, so
running it again is safe. `LESSON.md` explains how the script works.

## 4. Prove it is secure (same scan as step 2)

```bash
python3 scan/scan.py --project hwz --region us-east-1
```

Expect PASS, zero findings, exit code 0. Same scanner, same account, opposite
result. The delta between step 2 and step 4 is the security lesson, made real.

## 5. Tear it down

```bash
cd foundation
terraform destroy -var-file=baseline.tfvars -auto-approve
cd ..
```

## The infrastructure-as-code alternative to step 3

The fix script remediates a live account, which is what you do in an incident.
To make the same fixes permanent and version-controlled, apply the hardened
variables instead and re-scan:

```bash
cd foundation && terraform apply -var-file=hardened.tfvars -auto-approve && cd ..
python3 scan/scan.py            # also PASS
```

The program teaches both: remediate live now, then codify so it never regresses.

Always destroy when you finish a session. A lab left running is a bill and a risk.

## Offline check (no AWS, no cost)

You can prove the scanner logic itself any time, with no account:

```bash
python3 scan/scan.py --selftest    # checks catch the insecure fixture, pass the secure one
python3 fix/fix.py  --selftest     # proves the fix closes every finding the scan reports
```

The scanner selftest runs the checks against a known-insecure and a known-secure
fixture. The fix selftest applies the remediation to the insecure fixture and
confirms the scanner then finds nothing, so you know the fix closes exactly what
the scan opens before you run anything live.

---

Build it. Release it. Break it. Harden it.

(C) 2026 Vigilantia Technologies INC. All rights reserved. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
