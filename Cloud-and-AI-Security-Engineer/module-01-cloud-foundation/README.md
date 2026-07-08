<p align="center">
  <img src="../../assets/hackwithzachlogo.jpg" alt="HackWithZach" width="120">
</p>

<h1 align="center">Cloud and AI Security Engineer: From Zero to Hired</h1>
<p align="center"><strong>Module 1: The Cloud Foundation</strong></p>
<p align="center">Cybersecurity Education That Gets You Hired, Promoted and Paid.</p>
<p align="center"><em>Build it. Release it. Break it. Harden it.</em></p>

---

> FULL COHORT MATERIAL. This repository is licensed to enrolled HackWithZach Full cohort members only. It is not part of the Light tier. Do not share, post, or redistribute it. See `LICENSE.md`.

## What this is

The cloud foundation for the flagship course, as one modular Terraform codebase you build, deploy, prove insecure, harden, and tear down with your own hands. This is the reference. In the course you build your own version of it from scratch, one component at a time, and prove each one with the scanner before moving on.

## Read these first

At the repository root (two levels up from this module):

- `DISCLAIMER.md` before you deploy anything. Educational use, sandbox accounts only, you own the costs.
- `SECURITY.md` for the no-secrets rules and the pre-commit hook.
- `LICENSE.md` for what you may and may not do with this repo.

## The four-step lab (the format for every project)

1. Deploy the insecure stack (`foundation/`, Terraform) and understand why each piece is insecure.
2. Scan it with `scan/scan.py` to identify the insecure structure.
3. Fix it with `fix/fix.py` to remediate every finding.
4. Run the same scan again and watch every check pass. Then tear it down.

Every step is explained in `LESSON.md`, and every script is validated offline (`--selftest`) so the fix provably closes exactly what the scan flags.

## The material (in this module folder)

| File | What it is |
|---|---|
| `TEACH.md` | The chapter. Starts with the whole picture, then builds. |
| `LESSON.md` | The four-step lab, with the code behind each step explained. |
| `RUNBOOK.md` | The exact commands: deploy, scan, fix, scan, destroy. |
| `HARDEN.md` | The hardening pass, control by control. |
| `HOMEWORK.md` | The week-1 co-build assignment. |
| `foundation/` | The modular Terraform: VPC, KMS, IAM, S3, Secrets, CloudTrail, observability. |
| `scan/` | `hwz-scan`, the scanner that identifies insecure structure (steps 2 and 4). |
| `fix/` | `hwz-fix`, the remediation script that closes every finding (step 3). |

## The loop, in one breath

```bash
git config core.hooksPath .githooks          # turn on the secret-scan hook
cd foundation && terraform init
terraform apply -var-file=baseline.tfvars     # build the weak stack
cd .. && python3 scan/scan.py                 # prove it insecure (FAIL)
cd foundation && terraform apply -var-file=hardened.tfvars
cd .. && python3 scan/scan.py                 # prove it secure (PASS)
cd foundation && terraform destroy -var-file=hardened.tfvars
```

Full detail in `RUNBOOK.md`.

---

By Zach Marcy. Cybersecurity Architect and Mentor. 20+ years in IT, 6 in cybersecurity. I design and secure cloud environments that deploy and secure APIs and AI.

© 2026 Vigilantia Technologies INC. All rights reserved. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
