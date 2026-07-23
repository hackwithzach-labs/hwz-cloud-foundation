# Full deployment walkthrough

This is the complete, start-to-finish guide to deploying the cloud foundation, proving it insecure, fixing it, proving it secure, and tearing it down. It assumes you have never done this before. Follow it in order. Everything runs in an isolated sandbox AWS account and, if you tear down the same day, costs pennies.

Read `DISCLAIMER.md` before you begin. Use a sandbox account you own, never production and never your employer's.

One note on the console. Parts 1 to 3 use the AWS web console to create the account, set a budget alarm, and mint your first credential. That is the one-time bootstrap you cannot avoid, because a command line has no credentials until you make the first one. From Part 4 onward, every resource is code and every action is a command. We never build infrastructure by clicking. Chapter 8 explains why in full.

## Part 0: what you will spend

Almost everything here is free: the VPC, subnets, security group, and route tables cost nothing. The S3 buckets, CloudWatch logs, and Secrets Manager secret are pennies at this scale. The only standing charge is the KMS key, about one dollar per month, prorated. If you deploy and destroy in the same session you will spend a few cents. Set a budget alert in Part 1 so there are no surprises.

## Part 1: the AWS sandbox account

1. Create or choose an isolated AWS account. A brand-new account on the free tier is ideal. Do not use an account that holds anything real.
2. Set a billing alarm so you are warned if anything runs longer than you expect. In the console, go to Billing and Cost Management, then Budgets, and create a small monthly budget (for example five dollars) with an email alert. This is good hygiene and takes two minutes.
3. Decide your region. This guide uses `us-east-1`, which matches the defaults. If you use another region, change it consistently everywhere below and in `baseline.tfvars`.

## Part 2: install the tools

You need three tools: the AWS CLI, Terraform, and Python 3.

On Windows (PowerShell), the simplest path is winget:

```powershell
winget install --id Amazon.AWSCLI
winget install --id HashiCorp.Terraform
winget install --id Python.Python.3.12
```

On macOS with Homebrew:

```bash
brew install awscli terraform python3
```

On Linux, use your package manager for the AWS CLI and Python, and install Terraform from HashiCorp's apt or yum repository.

Verify all three, and confirm Terraform is 1.5 or newer:

```powershell
aws --version
terraform version
python --version
```

## Part 3: give the CLI short-lived credentials, without storing a secret

Terraform and the scripts act as you, using the credentials your CLI holds. We do NOT store a long-lived credential to do this. Writing an access key to `~/.aws/credentials` is exactly `T1552.001`, credentials in files, the technique this whole foundation defends against, so we use AWS IAM Identity Center with short-lived login instead: you log in once per session, the credentials expire in hours, and nothing secret lands on disk.

1. In the sandbox account console, open IAM Identity Center and enable it. On a fresh standalone account this also creates an AWS Organization with this account as its management account, which is fine for a lab. Create a user for yourself, create a permission set (`AdministratorAccess` for this disposable lab), and assign your user to the account with that permission set. Copy the AWS access portal "start URL" from the dashboard.

2. Configure the CLI for SSO, once. This writes only the portal URL, region, and role name to `~/.aws/config`, no secret:

```powershell
aws configure sso
# SSO start URL:  <paste the portal URL>
# SSO region:     us-east-1
# then pick the account + AdministratorAccess permission set, and name the profile: hwz-lab
```

3. Log in at the start of each session, and point everything at the profile:

```powershell
aws sso login --profile hwz-lab
$env:AWS_PROFILE = "hwz-lab"      # macOS/Linux: export AWS_PROFILE=hwz-lab
```

`aws sso login` opens your browser; approve it and the CLI caches a short-lived token that expires on its own. Terraform, boto3, and the scanner all read this profile natively.

4. Confirm you are pointed at the right account. This should print the sandbox account ID:

```powershell
aws sts get-caller-identity
```

Look at the `Account` field and make sure it is the sandbox, not somewhere real. This one check prevents almost every bad-day scenario. If a command later fails with an expired-token error, that is the design working; run `aws sso login --profile hwz-lab` again.

## Part 4: get the repository and set up Python

1. If you have not already, clone the repo and move into this module:

```powershell
git clone https://github.com/hackwithzachcs/hwz-cloud-foundation.git
cd hwz-cloud-foundation\Cloud-and-AI-Security-Engineer\module-01-cloud-foundation
```

2. Turn on the secret-scanning hook and set up a Python environment for the scripts:

```powershell
git config core.hooksPath ..\..\.githooks
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r scan\requirements.txt
```

3. Prove the scripts are sound before touching AWS. Both selftests run offline:

```powershell
python scan\scan.py --selftest
python fix\fix.py --selftest
```

You should see both report PASS. The fix selftest proving zero findings is your guarantee that the remediation closes exactly what the scan flags.

## Part 5: Step 1, deploy the insecure stack

```powershell
cd foundation
terraform init
terraform plan "-var-file=baseline.tfvars"
terraform apply "-var-file=baseline.tfvars"
```

The quotes around the var-file argument matter on Windows. PowerShell sometimes splits an unquoted argument at the equals sign, and Terraform reports too many command line arguments. Quoting it keeps it whole. The same applies to every var-file argument in this guide.

`init` downloads the AWS provider. `plan` shows you everything it will create; read it. `apply` builds it, and asks you to type `yes` to confirm. It should finish with `Apply complete` and a list of outputs including the VPC id, the data bucket name, and the KMS key ARN. If it applied with no errors, Step 1 is done. The stack is live and wide open on purpose.

## Part 6: Step 2, scan and prove it insecure

```powershell
cd ..
python scan\scan.py --project hwz --region us-east-1
```

Expect a FAIL with around a dozen findings and a non-zero exit code. Read every line. Each one names a real weakness and the risk it creates. Open the AWS console and confirm one or two of them with your own eyes, for example that the data bucket has no default encryption. This is the break step. You are auditing your own build.

## Part 7: Step 3, fix it

First capture the KMS key ARN that the encryption fixes need, then dry-run the fix, then apply it:

```powershell
$KEY = terraform -chdir=foundation output -raw kms_key_arn

python fix\fix.py --project hwz --region us-east-1
python fix\fix.py --project hwz --region us-east-1 --kms-key-arn $KEY --commit
```

The first `fix.py` run is a dry run: it prints every remediation and the exact AWS API call it will make, and changes nothing. Read it. The `--commit` run applies the fixes. It is idempotent, so running it twice is safe. `LESSON.md` explains how each fix works.

## Part 8: Step 4, prove it secure

Run the same scanner again:

```powershell
python scan\scan.py --project hwz --region us-east-1
```

Expect PASS, zero findings, exit code 0. Same tool, same account, opposite result. The difference between Part 6 and Part 8 is the entire lesson.

## Part 9: tear it down

The fix script created one resource that Terraform does not track, a VPC flow log, so remove it first, then destroy everything Terraform made.

```powershell
# remove the flow log the fix script created (config drift, a real lesson in itself)
$VPC = terraform -chdir=foundation output -raw vpc_id
$FL = aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$VPC" --query "FlowLogs[].FlowLogId" --output text
if ($FL) { aws ec2 delete-flow-logs --flow-log-ids $FL }

# destroy the stack
terraform -chdir=foundation destroy -var-file=baseline.tfvars
```

`destroy` asks you to type `yes`. When it finishes, the only thing left is the KMS key, which enters a seven-day pending-deletion window rather than vanishing instantly. That is normal and it stops billing. Everything else is gone.

Confirm nothing lingers: in the console, check that the VPC, the buckets, and the CloudTrail trail are gone. A clean teardown is part of the discipline.

## The infrastructure-as-code alternative to Steps 3 and 4

Instead of the fix script, you can make the same fixes permanent and version-controlled by applying the hardened variables, then re-scanning:

```powershell
terraform -chdir=foundation apply -var-file=hardened.tfvars
python scan\scan.py --project hwz --region us-east-1     # also PASS
terraform -chdir=foundation destroy -var-file=hardened.tfvars
```

This path has no flow-log drift, because Terraform manages the flow log itself. The program teaches both because the job needs both: remediate live under pressure, then codify so it never regresses.

## Troubleshooting

If `aws sts get-caller-identity` fails, your credentials are not configured; re-run `aws configure`.

If Terraform says no valid credential sources, confirm the CLI works first with the identity check above, and that your region matches.

If `apply` fails with an access-denied error, the IAM identity is missing a permission; in the sandbox, confirm it has `AdministratorAccess`.

If the scanner or fix script cannot find boto3, activate the virtual environment and re-run `pip install -r scan\requirements.txt`.

If `destroy` fails saying a bucket is not empty, the data and trail buckets use force-destroy so this should not happen, but if it does, empty the bucket in the console and re-run destroy.

If a KMS-related error appears during the trail encryption fix, confirm you passed `--kms-key-arn` with the value from `terraform output`.

---

Build it. Release it. Break it. Harden it.

By Zach Marcy. Cybersecurity Architect and Mentor. 20+ years in IT, 6 in cybersecurity. I design and secure cloud environments that deploy and secure APIs and AI.

© 2026 Vigilantia Technologies INC. All rights reserved. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
