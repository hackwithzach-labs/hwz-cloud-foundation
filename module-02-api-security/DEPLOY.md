# Full deployment walkthrough: the API layer on AWS

This is the complete, start-to-finish guide to deploying the Pillar 2 API layer on real AWS: composing the hardened foundation you built in Chapter 8, adding a Bedrock interface endpoint in your private subnets and a least-privilege API role, invoking a real model once, verifying it all in the console, and tearing it down. It assumes you have already run the local loop in `RUNBOOK.md`, so you understand the four controls before you spend a cent.

Read `DISCLAIMER.md` before you begin. Use a sandbox account you own, never production and never your employer's. If you deploy and destroy in the same session, this costs a few cents.

Everything in Chapter 8's `DEPLOY.md` about the AWS bootstrap, the sandbox account, installing the tools, and configuring credentials still applies. If you have not done that, do it first; this guide picks up from a working AWS CLI pointed at your sandbox.

## Part 0: what you will spend

The foundation resources are the same pennies as Chapter 8, plus one new standing charge: the Bedrock interface endpoint, billed per hour it exists (roughly a few cents an hour, a bit over a dollar a day if you forget it). There are no NAT gateways by design. A single real model call to Claude 3 Haiku with a tiny token ceiling costs a fraction of a cent. Apply at the start of a session, destroy at the end, and set the budget alarm from Chapter 8 so there are no surprises. Remember the rule: a budget alarm alerts, it does not hard-stop. Your real guardrail is the destroy command and the always-on breaker in `app/config.py`.

## Part 1: prerequisites

1. A short-lived login to your sandbox account through IAM Identity Center, the same one you set up in Chapter 8 (`module-01-cloud-foundation/DEPLOY.md`, Part 3). No stored keys. Log in and point the session at the profile:

```bash
aws sso login --profile hwz-lab
export AWS_PROFILE=hwz-lab       # Windows PowerShell: $env:AWS_PROFILE="hwz-lab"
aws sts get-caller-identity
```

Read the `Account` field and make sure it is the sandbox, not somewhere real. If a command later fails with an expired-token error, that is the design working; run `aws sso login --profile hwz-lab` again.

2. The module, a Python environment, and the dependencies (now including boto3 for the real model call):

```bash
cd module-02-api-security
python3 -m venv .venv && source .venv/bin/activate
pip install -r app/requirements.txt
```

3. You have already run the local loop from `RUNBOOK.md` and understand the four controls. The cloud step below runs the app HARDENED only. You never deploy the weak profile against a real model.

## Part 2: enable Bedrock model access

Bedrock does not let you invoke a foundation model until you have explicitly enabled access to it in the account. This is a one-time console step per account.

1. In the AWS console, open Amazon Bedrock in your region (`us-east-1` matches the defaults).
2. In the left nav, open Model access, then Manage model access.
3. Enable Anthropic Claude 3 Haiku. Access is usually granted immediately.

If you skip this, the real call below fails with an AccessDenied that names the model, and that error is itself the lesson: model access is a deliberate grant, not a default.

## Part 2b: see a real Bedrock call, naked, at the command line

Before wrapping it in anything, invoke the model directly and read the raw answer. A "Bedrock call" is one InvokeModel request: model id + prompt + max_tokens in, a completion and a token count out, authenticated by your short-lived login and billed a fraction of a cent. The `--cli-binary-format raw-in-base64-out` flag lets you pass the body as plain JSON.

```bash
aws bedrock-runtime invoke-model \
  --model-id anthropic.claude-3-haiku-20240307-v1:0 \
  --cli-binary-format raw-in-base64-out \
  --region us-east-1 \
  --body '{"anthropic_version":"bedrock-2023-05-31","max_tokens":60,"messages":[{"role":"user","content":[{"type":"text","text":"In one sentence, what is least privilege?"}]}]}' \
  bedrock-out.json

cat bedrock-out.json
```

The answer is under `content[0].text` and a `usage` block reports `input_tokens` and `output_tokens`. That is the whole transaction the API will wrap with the four controls. Meet the call first; then secure it.

## Part 3: read the plan before you apply

The Terraform root in `foundation/` does not redefine a VPC, a key, or an identity. It composes the module-01 foundation pinned to its hardened values, and adds only the two things Pillar 2 needs: a Bedrock interface endpoint in the private subnets, and a workload role the API assumes. Initialize and read the plan:

```bash
cd foundation
terraform init
terraform plan
```

Read what it will create before it exists. You are looking for the whole module-01 foundation (VPC, subnets, KMS key, IAM role, S3, Secrets Manager, CloudTrail, CloudWatch) plus two new resources: `aws_vpc_endpoint.bedrock_runtime` and `aws_iam_role.api` with its policy. The foundation flags are all fixed to their strong values in this root; it does not expose a weak option, so a pillar deploy can never stand up a weak foundation by accident. That is the locked rule: foundation hardened, new layer weak, and the new layer's weakness lives in the app, not here.

## Part 4: deploy

```bash
terraform apply
```

Type `yes` when it asks. It should finish with `Apply complete` and a set of outputs. The ones that matter:

- `bedrock_endpoint_id` the interface endpoint in your private subnets.
- `api_role_arn` the least-privilege role the API assumes in production.
- `secret_arn` the foundation secret the role may read.

If it applied with no errors, the infrastructure is live.

## Part 5: verify with your eyes, in the console

Deploying is not believing. Confirm the two new resources are what you intended.

**The private endpoint.** Open the VPC console, go to Endpoints, and find the `bedrock-runtime` endpoint. Confirm it is an Interface endpoint, that its subnets are your two PRIVATE subnets, and that its security group allows 443 from the VPC CIDR only. There is no public route to it. This is the model path that a workload inside the VPC uses, reachable from inside and nowhere else.

**The least-privilege role.** Open IAM, find `hwz-lab-api-role`, and read its inline policy. It has exactly two statements: invoke ONE Bedrock model family, and read ONE secret. No `bedrock:*`, no `secretsmanager:*`, no wildcards. That is least privilege you can see on the screen, and it is the identity your API assumes in production so that a stolen API credential can do nothing but call the one model and read the one secret.

## Part 6: invoke a real model, once, hardened only

Now make it real. Run the app hardened, with the real-model switch on, and send exactly one request.

```bash
cd ..
HWZ_PROFILE=hardened HWZ_USE_REAL_MODEL=true uvicorn app.main:app --port 8000
```

In a second terminal, mint a valid token and send one small request:

```bash
TOKEN=$(python3 -c "import jwt; print(jwt.encode({'sub':'zach','aud':'hwz-inference-api'},'lab-demo-secret-not-for-production',algorithm='HS256'))")
curl -s localhost:8000/v1/complete -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "In one sentence, what is least privilege?", "max_tokens": 60}'
```

A healthy response is a real sentence from Claude, with a real token count and a real (tiny) cost, plus a structured audit line in the server log. That is the whole pipeline end to end: audience-checked, schema-bounded, cost-capped, audited, and now answered by a real model.

**Be honest about the path.** Running the app on your laptop, it reaches Bedrock over the public AWS API using your short-lived SSO login, not through the private endpoint you just deployed. The endpoint and the role are the PRODUCTION path: when this same app runs on an instance or a Lambda inside your private subnets, it assumes `api_role_arn` and its Bedrock traffic goes through `bedrock_endpoint_id`, never touching the internet. You deployed and verified that production path in Part 5; Part 6 proves the app works against a real model. Standing up the in-VPC compute is the Pillar 2 extension, and the endpoint and role are already waiting for it.

**The rules that keep this cheap and safe.** Hardened profile only. The cheapest model (Haiku), which the role is also scoped to. A tiny `max_tokens`, and the always-on breaker in `app/config.py` clamps it to 128 and caps the process at 25 calls no matter what. And never, ever point the flooding attack (A3) at this. The flood is a mock-only demonstration. Cloud billing alerts, it does not hard-stop, so the code is your real guardrail.

## Part 7: tear it down

Stop the app with Ctrl+C, then destroy the infrastructure so the one hourly resource stops billing:

```bash
cd foundation
terraform destroy
```

Type `yes`. When it finishes, everything is gone except the KMS key, which enters its seven-day pending-deletion window rather than vanishing instantly (normal, and it stops billing). Confirm with your eyes: in the VPC console, the Bedrock endpoint is gone; in IAM, the api-role is gone. A clean teardown is part of the discipline, and the interface endpoint is the one resource you most want gone before you close the laptop.

## Troubleshooting

If `terraform apply` fails with access denied, the CLI identity is missing a permission; in the sandbox, confirm it has `AdministratorAccess` and that `aws sts get-caller-identity` shows the right account.

If the real call in Part 6 returns AccessDenied naming the model, you have not enabled Bedrock model access (Part 2), or your CLI identity cannot invoke it. Enable Haiku and retry.

If the real call returns a ValidationException about the body, confirm your region matches the model and that `HWZ_MODEL_ID` (default Claude 3 Haiku) is available in that region.

If the call is slow or returns a throttling error, that is Bedrock rate-limiting a brand-new account; wait and retry a single request. Do not loop it.

If uvicorn cannot import boto3, activate the virtual environment and re-run `pip install -r app/requirements.txt`.

If `terraform destroy` leaves the endpoint, re-run destroy; interface endpoints occasionally take a second pass. Confirm in the VPC console that it is gone.

---

Build it. Release it. Break it. Harden it.

By Zach Marcy. Cybersecurity Architect and Mentor. 20+ years in IT, 6 in cybersecurity. I design and secure cloud environments that deploy and secure APIs and AI.

© 2026 Vigilantia Technologies INC. All rights reserved. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
