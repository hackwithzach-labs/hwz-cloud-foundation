# Security practices for this repo

We teach cloud security. The repo has to hold to the standard it teaches. These are the rules for anyone working in it.

## Never commit secrets

No AWS keys, no passwords, no API tokens, no private keys, no `.env` files, no Terraform state. Ever. The line is simple: settings get committed, credentials never do.

What protects you here:

- `.gitignore` blocks `*.tfstate`, `*.tfvars` (except the two safe flag files and `*.example`), `.env`, and `*.pem`.
- A pre-commit hook in `.githooks/` scans every staged change for common credential patterns and blocks the commit if it finds one. Turn it on once, per clone:

```bash
git config core.hooksPath .githooks
```

- For a heavier net, run a dedicated scanner such as gitleaks or trufflehog in CI before anything merges.

## Credentials come from your environment, not the code

Terraform reads AWS credentials from your configured CLI profile or environment variables. There is no access key anywhere in this repo, and there never should be. The Secrets Manager module generates its password at apply time with `random_password`, so even the lab secret is not written into source.

## Use an isolated sandbox account

Every deploy in this course runs in a throwaway AWS account that holds nothing real. Not production. Not your employer's account. If a lab resource is ever exposed, the blast radius is a sandbox you were about to destroy anyway.

## Tear down when you finish

`terraform destroy` at the end of every session. A lab left running is a bill and an exposed surface. The habit of clean teardown is part of the discipline, not an afterthought.

## If something leaks

Rotate it immediately at the source (AWS, Stripe, wherever), then remove it from history. A secret that touched a git history is compromised even after you delete the line, so rotation comes first, cleanup second.

---

By Zach Marcy. Cybersecurity Architect and Mentor. 20+ years in IT, 6 in cybersecurity. I design and secure cloud environments that deploy and secure APIs and AI.

© 2026 Vigilantia Technologies INC. All rights reserved. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
