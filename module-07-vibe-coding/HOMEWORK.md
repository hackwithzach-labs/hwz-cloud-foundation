# Chapter 14 homework — build the gate, then try to sneak past it

**1. Catch the AI.** Ask an assistant to generate a Terraform module for "an S3
bucket and a role to use it." Accept it unedited. Save it beside
`generated/weak/main.tf` and run the gate against its plan:

```bash
terraform plan -out plan.out && terraform show -json plan.out > plan.json
python3 scan/scan.py --plan plan.json
```

Record every finding. This is your baseline, and it is almost certainly not
clean.

**2. Wire the gate.** Put `ci/gate.sh` into a CI step so a non-zero exit fails
the build. Confirm the generation from step 1 now fails the pipeline.

**3. Re-prompt with requirements.** Ask again, handing the assistant the
Chapter 8 control map in the prompt (`generated/prompts/02-hardened-prompt.txt`
is the shape). Run the same gate and confirm PASS. Keep both prompts.

**4. Add the commit and dependency gates.** Confirm the Chapter 8 secret
pre-commit hook blocks an inline key, and add any SCA tool that flags a
known-vulnerable package.

**5. Try to sneak one past.** Now play attacker against your own gate. Get the
assistant to generate something insecure in a way the scanner misses — a
subtly-scoped-but-still-too-broad policy, a secret in an unusual field, a
`block_public_access` with three of four switches on. Whatever slips through is
a new rule you add to the scanner.

That last step is the pillar. Generate, gate, find the gap, close the gap. A
gate you have personally tried to defeat is worth more than one you assume
works.

Turn in: the two prompts, the two plans, the failing CI run next to the passing
one, and one rule you added to the scanner after step 5.

© 2026 Vigilantia Technologies INC.
