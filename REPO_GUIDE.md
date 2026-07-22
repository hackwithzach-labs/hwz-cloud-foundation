# Your Security Portfolio Repo: What Goes In, What Never Does

The HackWithZach guide to publishing your builds on GitHub without publishing your account. Free to every student. Read it before your first push, and run the checklist before every push after that.

Build it. Release it. Break it. Harden it.

(c) 2026 Vigilantia Technologies INC. All rights reserved. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.

## The one idea this whole guide stands on

Git never forgets. Deleting a file in a new commit removes it from the folder, not from history, and anyone can pull the old version back out with one command. Public means permanent: assume everything you have ever pushed has been copied by scrapers within minutes. So the discipline is not cleaning up after a leak. It is never letting the sensitive thing touch a commit in the first place.

## What BELONGS in your portfolio repo

Your Terraform source (main.tf, variables.tf, modules, outputs). A tfvars EXAMPLE file with placeholder values (account_id = "123456789012", never your real one). The .terraform.lock.hcl (public hashes, makes the build reproducible). A .gitignore that blocks the dangerous files (below). Your README with the architecture diagram PNG at the top and a narration paragraph under it. The .drawio diagram source next to the PNG. Evidence artifacts AFTER redaction. A LICENSE and a how-to-run section with the sandbox and budget-alarm warnings.

## What NEVER goes in, and why

| Never commit | Why | How it usually leaks |
|---|---|---|
| Credentials: access keys, session tokens, .aws/, .env, \*.pem | Instant account compromise; bots scan public GitHub within seconds | Hardcoded to test, or .env swept up by git add . |
| terraform.tfstate and backups | State stores real IDs and can store SECRET VALUES in plain text | Local state committed before a remote backend existed |
| Terraform PLAN files | A plan file is a zip with an embedded state snapshot: account ID, every ARN, every resource ID | Saved as tfplan with no extension, so \*.tfplan never matches it |
| Your real terraform.tfvars | Carries your account ID and personal values | Committed instead of the .example |
| Your AWS account ID anywhere | Not a credential, but enables targeting and enumeration | Console screenshots (top-right), pasted ARNs, plan output |
| Raw console screenshots | Account ID, ARNs, emails, IPs in frame | Evidence habit minus redaction habit |
| CloudTrail exports, real log lines | Full of account IDs, IPs, identities | Pasted as log-review proof |
| .terraform/ directory | Provider binaries, cached values | Missing ignore line |

The pattern: source code describes the SHAPE of the system and is safe to share. What must never leak is anything describing YOUR INSTANCE of it: identifiers, addresses, state, secrets. Publish the blueprint, never the house keys, and not the house address either.

## The .gitignore that catches every incident above

```
.terraform/
*.tfstate
*.tfstate.*
crash.log
*.tfplan
tfplan*
plan.out
terraform.tfvars
*.auto.tfvars
.env
.env.*
*.pem
*credentials*
.vscode/
.DS_Store
```

The pair `*.tfplan` AND `tfplan*` matters: ignore patterns match filenames literally, and the file actually created is often named just `tfplan`, which slips past `*.tfplan`. That exact one-character-of-filename miss has published real account IDs. Copy this into every new repo BEFORE the first commit.

## Three layers of protection

1. The ignore file: stops the accident at git add.
2. A pre-commit secret scan with gitleaks (free): `gitleaks detect --source . -v` to scan now including history; wire `gitleaks protect --staged` into a pre-commit hook so every commit is checked. Verify the hook by staging a fake AWS key and watching the commit refuse.
3. GitHub push protection: repo Settings, Code security, enable Secret scanning + Push protection (free on public repos). The server-side net for machines that never got the hook.

## Before every push: the 60-second checklist

1. `git status`: anything staged that describes YOUR instance (state, plan, tfvars, logs)?
2. `git diff --staged`: search for your 12-digit account ID and arn:aws lines carrying it.
3. New screenshots: account ID (console top-right), emails, IPs blocked out with solid rectangles (blurs have been reversed).
4. `gitleaks detect` passes clean.
5. README still teaches safe running (sandbox account, budget alarm, destroy at the end).

## When a leak already happened: the remediation walkthrough

1. Assess the class. A credential is CRITICAL: rotate it at the source FIRST, within minutes, before any git surgery, because scrapers already have it. IDs and ARNs are moderate: no rotation exists; do the history surgery and treat the values as permanently public.
2. Find every copy: `git log --all --oneline -- <path>`, then `git show <commit>:<path>` to prove what an outsider can recover. Seeing your own account ID come back out of a deleted file is the lesson that sticks.
3. Rewrite history with git filter-repo (`pip install git-filter-repo`): `git filter-repo --invert-paths --path tfplan --path terraform.tfstate`, then `git push --force --all` and `--tags`. For a days-old repo the honest shortcut is fine: delete the GitHub repo, delete .git, re-init clean with the correct .gitignore, push a fresh first commit.
4. Re-verify BOTH ways: gitleaks clean and `git log --all -- <path>` empty (machine), plus the GitHub commit-history view and search showing the file gone from every commit (eyes). Forks and clones made before the rewrite keep the old history, which is why rotation, not rewriting, is the real fix for credentials.
5. State the breach headline your leak class could have caused, and add the missing control so it cannot recur.

## Screenshot redaction rule

Ten seconds per console screenshot before it enters the evidence folder: solid black rectangle over the account ID, emails, public IPs, and any ARN carrying the account number. What remains should teach the control, not identify the account.

Cybersecurity Education That Gets You Hired, Promoted and Paid.
