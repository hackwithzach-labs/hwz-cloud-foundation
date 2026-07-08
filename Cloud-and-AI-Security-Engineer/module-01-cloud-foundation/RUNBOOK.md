# Runbook: prove the loop on real AWS

This is the loop the whole course runs on. You build it, deploy it, prove it is
insecure with the scanner, harden it, prove it is secure, then tear it down. Do
this once here on the foundation and you know the machinery works. Every pillar
repeats the same five moves.

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

## 3. Harden it

```bash
cd foundation
terraform plan  -var-file=hardened.tfvars     # read the diff first
terraform apply -var-file=hardened.tfvars -auto-approve
cd ..
```

## 4. Prove it is secure

```bash
python3 scan/scan.py --project hwz --region us-east-1
```

Expect PASS, zero findings, exit code 0. Same scanner, same account, different
posture. The delta between step 2 and step 4 is the security lesson, made real.

## 5. Tear it down

```bash
cd foundation
terraform destroy -var-file=hardened.tfvars -auto-approve
cd ..
```

Always destroy when you finish a session. A lab left running is a bill and a risk.

## Offline check (no AWS, no cost)

You can prove the scanner logic itself any time, with no account:

```bash
python3 scan/scan.py --selftest
```

It runs the checks against a known-insecure and a known-secure fixture and
confirms the insecure one fails and the secure one passes.

---

Build it. Release it. Break it. Harden it.

(C) 2026 Vigilantia Technologies INC. All rights reserved. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
