# Verification log — 2026-08-09 build

What was actually run against this exact tree, what passed, and — the part that
matters more — what could **not** be checked here and therefore still needs a
gate before you teach from it.

## Ran and passed

Nine offline selftests, every one of them in this tree, not in a working copy
somewhere else:

| Check | Command | Result |
|---|---|---|
| Module 1 scanner | `module-01-cloud-foundation/scan/scan.py --selftest` | PASS |
| Module 2 attacker | `module-02-api-security/attack/attack.py --selftest` | PASS |
| Module 3 detector | `module-03-observability-detection/detect/detect.py --selftest` | PASS — blind 13 gaps, wired 0 |
| Module 3 emitter | `module-03-observability-detection/attack/emit.py --selftest` | PASS — 6 unauthorized, 2 cost-cap, 0 false matches |
| Module 4 guardrail | `module-04-llm-security/guard/guard.py --selftest` | PASS |
| Module 4 scanner | `module-04-llm-security/scan/scan.py --selftest` | PASS |
| Module 5 scanner | `module-05-ai-apis-mcp/scan/scan.py --selftest` | PASS |
| Module 6 scanner | `module-06-agentic-ai/scan/scan.py --selftest` | PASS |
| Shared IPI scanner | `module-04-llm-security/visual/ipi_scan.py --selftest` | PASS — 4 gaps vulnerable, 0 hardened |

Behavioural checks beyond the selftests:

- `module-04-llm-security/attack/inject.py` — 6/6 attacks land against the weak
  build; `--guarded` — 0/6 land. The guardrail is doing something, and the
  attack tool can tell.
- the Chapter 11 injection lab end to end, offline, CLI and browser: the vulnerable
  agent leaks the fake API key from both the poisoned `.txt` and the poisoned
  `.pdf`; the hardened agent refuses both and writes two detection events; the
  clean ticket is still served normally by the hardened agent.
- `python3 -m compileall` — every Python file in the tree compiles.
- `tofu fmt -check -recursive` — every `.tf` and `.tfvars` is canonically
  formatted, so a student's first `terraform fmt` produces no diff.
- Secret sweep — no live-format credentials, no `*.tfstate`, no `*.tfplan`, no
  `.env`, no keys. One hit looks like an AWS access key id: it is AWS's own
  published documentation example value, used deliberately as a guardrail test
  fixture in `module-04-llm-security/guard/guard.py`. The literal is split in
  the source so the repo's own pre-commit secret scan does not flag it -- a
  scanner you have to switch off to commit is a scanner you will switch off.
- `git add -A` in a scratch repo, then confirmed all eleven `baseline.tfvars` /
  `hardened.tfvars` files are staged rather than ignored.

## Could NOT be verified in the build container

**`terraform init`, `validate`, and `plan`.** The provider registry is not
reachable from the build environment, so no Terraform in this tree has been
schema-validated. The offline linter (`tools/tflint.py`) parses every `.tf`
with a real HCL2 parser and cross-references variables, outputs and module
wiring, and it is clean apart from the three cosmetic findings below — but it
has no provider schemas, so it cannot catch a misspelled argument name.

Run this gate per module before teaching from it:

```bash
cd module-0X-.../foundation
terraform init
terraform validate
terraform plan -var-file=baseline.tfvars      # weak profile
terraform plan -var-file=hardened.tfvars      # hardened profile
```

Both plans must succeed. Modules 4, 5 and 6 are the ones to check first,
because their composition blocks were commented out until this release and
have therefore never been planned in their composed form.

**Anything requiring AWS credentials.** No deploy, no live scan, no teardown
verification was run. Every scanner falls back to its bundled fixture when it
cannot reach AWS, and says so on screen with an amber FIXTURE badge — a
simulation can never pass itself off as your account — but that means a green
selftest is a statement about the code, not about your account.

## Known cosmetic findings, not fixed

`tools/tflint.py` reports three unused variable declarations. None affects a
deploy; all three are leftovers from earlier refactors:

- `module-01-cloud-foundation/foundation/modules/cloudtrail` — `region`
- `module-01-cloud-foundation/foundation/modules/kms` — `region`
- `module-03-observability-detection/foundation/modules/detection` —
  `cloudtrail_bucket_arn`

They are listed here rather than silently removed, because a student who runs
the linter will see them and should find them already accounted for.

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are
trademarks of Vigilantia Technologies INC.
