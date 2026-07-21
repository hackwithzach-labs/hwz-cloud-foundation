# Module 1 Foundation: the Terraform baseline

This is the cloud foundation for the Cloud and AI Security Engineer course. It is one modular Terraform codebase that deploys clean on the first `apply`, then hardens by flipping flags. You will run it twice: once weak, once hardened, and read the diff between them. That diff is the lesson.

Build it. Release it. Break it. Harden it.

## What you get

Seven modules, composed by one root:

| Module | What it stands up | Weak in baseline | Strong when hardened |
|---|---|---|---|
| `vpc` | VPC, public + private subnets, IGW, routing, endpoint SG | endpoint open to `0.0.0.0/0`, no flow logs | SG locked to the VPC CIDR, flow logs on |
| `kms` | one customer-managed key the foundation shares | broad key policy, no rotation | scoped policy, rotation on, CloudTrail grant added |
| `iam` | a workload role your apps assume | broad `s3:* kms:* secretsmanager:*` grant | explicit deny on destructive actions |
| `s3` | the general-purpose data bucket | no encryption, no public-access block, no TLS enforcement, no versioning | KMS default encryption, public access blocked, TLS-only policy, versioning |
| `secrets` | a Secrets Manager secret, no rotation Lambda | AWS-managed key | foundation KMS key |
| `cloudtrail` | account trail plus its own correctly-policied log bucket | single region, no log validation, no data events, no KMS | multi-region, log validation, S3 data events, KMS encryption |
| `observability` | CloudWatch log groups plus the flow-logs role | log groups exist, nothing feeds them | VPC flow logs write here |

## Prerequisites

You need Terraform 1.5 or newer, an AWS CLI profile pointed at an ISOLATED SANDBOX account (never production, never your employer), and a region you are comfortable creating a handful of cheap resources in. Nothing here runs an EC2 instance or a NAT gateway, so the running cost is close to zero. The only thing that can cost money if you forget it is the KMS key, which is why you will destroy everything at the end.

## Run the weak stack

```bash
terraform init
terraform plan  -var-file=baseline.tfvars
terraform apply -var-file=baseline.tfvars
```

It applies with no errors. That is the point. It is wide open, but it is not broken. Now go look at what you built in the AWS console and understand every hole. `HARDEN.md` walks you through each one.

## Run the hardened stack

```bash
terraform plan  -var-file=hardened.tfvars   # read this diff carefully first
terraform apply -var-file=hardened.tfvars
```

Same code. Every flag flipped. Read the plan before you apply it. Each line in that diff maps to a specific control in `HARDEN.md`.

## Tear it down

```bash
terraform destroy -var-file=hardened.tfvars
```

Do this every time you finish a session. The CloudTrail buckets use `force_destroy` so the teardown is clean.

## How the pillars use this

Each pillar (LLM, AI APIs and MCP, Agentic AI, Vibe Coding) ships its own root that calls only the modules it needs and reads the outputs here. Pillar 2 reads `private_subnet_ids` and `endpoint_security_group_id` to place a Bedrock VPC endpoint. Nothing in a pillar re-declares the VPC or the key. That is the whole reason the foundation is modular instead of one golden template.

## The line between settings and secrets

`providers.tf`, `variables.tf`, `main.tf`, and the `*.tfvars.example` are safe to commit. `.gitignore` blocks `*.tfstate` and real `*.tfvars`, because those are where credentials and state leak. Push the settings. Never push the state.

---

By Zach Marcy. Cybersecurity Architect and Mentor. 20+ years in IT, 6 in cybersecurity. I design and secure cloud environments that deploy and secure APIs and AI.

Cybersecurity Education That Gets You Hired, Promoted and Paid.

© 2026 Vigilantia Technologies INC. All rights reserved. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
