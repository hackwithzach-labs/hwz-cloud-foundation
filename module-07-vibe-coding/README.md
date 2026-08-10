# Module 7 — Vibe Coding Security (Chapter 14)

**Pillar 4.** The first three pillars secured the AI *in* your system. This one
secures the code the AI writes *for* your system.

This is the only module in the course that deploys nothing. There is no
account to scan, because the whole point is to catch the problem **before**
anything exists. It costs nothing to run, needs no credentials, and works
offline.

```
scan/scan.py          the pre-deploy gate: plan JSON in, Chapter 8 verdict out
scan/fixtures/        known-bad and known-good generations, plus a real plan
generated/weak/       AI output, unedited. Evidence, not a mistake to fix.
generated/hardened/   the same request with the control map in the prompt
generated/prompts/    both prompts, side by side. This is the actual lesson.
ci/gate.sh            the gate as one script a pipeline calls
ci/github-actions.yml the same gate wired in front of every apply
visual/app.py         the browser console, port 5114
```

## Run the loop

```bash
# 0. prove the gate before you trust it — offline, no AWS
python3 scan/scan.py --selftest

# 1. the AI's unedited output
python3 scan/scan.py --snapshot scan/fixtures/ai-generated-insecure.json
#    -> NAKED. 6 gap(s), 3 HIGH. exit 1.

# 2. the same request, with the Chapter 8 control map in the prompt
python3 scan/scan.py --snapshot scan/fixtures/ai-generated-hardened.json
#    -> PASS. exit 0.

# 3. the same gate against a real terraform plan
python3 scan/scan.py --plan scan/fixtures/plan-weak.json

# 4. the browser version of all of it
cd visual && pip install -r requirements.txt && python3 app.py   # :5114
```

Then read `generated/prompts/01-weak-prompt.txt` next to
`generated/prompts/02-hardened-prompt.txt`. Same assistant, same task, same
amount of your time. That difference is the cheapest security control in this
entire course.

## The two design decisions worth stealing

**This module defines no checks of its own.** A wildcard does not become a
different finding because a model wrote it. `scan/scan.py` is a *translator* —
Terraform plan JSON in, the Chapter 8 snapshot shape out — and the verdict
comes from `module-01-cloud-foundation/scan/scan.py`, unchanged. One definition
of "secure" across the whole course. It also makes the gate arguable in a code
review: the answer to "why did the build go red" is not "the AI linter said
so", it is "this is the control map we have applied since Chapter 8, applied
earlier."

**Account-level checks are deferred, out loud.** `check_cloudtrail` asks
whether the *account* has an audit trail. Point it at a module that creates a
bucket and a role and it reports HIGH forever, because a module is not supposed
to ship an account-wide trail. No amount of hardening satisfies it. A gate that
cannot be satisfied gets switched off, and a switched-off gate protects
nothing — so the artifact gate runs everything the artifact can answer and
prints the name of what it deferred. Deferred is not dropped: the Chapter 8
account scan still asks that question where it makes sense.

Both decisions are in `scan/scan.py`, commented at the point where they bite.

## Everything else in this pillar is a habit, not a tool

The secret pre-commit hook is the one from Chapter 8 (`git config
core.hooksPath .githooks`). The dependency check is any SCA tool your pipeline
already has. The review checklist is the "what gets hardened, and where" table
at the end of every previous chapter. Pillar 4 is not new tooling. It is
pointing the tools you already built at what the AI writes, before it runs,
every time, automatically.

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are
trademarks of Vigilantia Technologies INC.
