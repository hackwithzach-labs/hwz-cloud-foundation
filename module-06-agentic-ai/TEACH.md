# TEACH — Module 6: Agentic AI (Pillar 3)

Start with the end in mind. By the end, the student has taken an autonomous
agent — a model in a loop, calling tools, carrying memory toward a goal —
deployed it with every control off, and watched four things a single tool call
could never do: its goal gets rewritten by a poisoned observation, a note it
saved to its own memory turns malicious on a later step, the loop runs away, and
a chain of harmless-looking steps ends in an irreversible action no human ever
approved. Then they lock all six doors and watch each abuse die somewhere
different. This is the code behind **Chapter 13**, and it runs the locked loop:
deploy naked, scan, attack, harden, scan, attack, review logs.

## The mental model

Pillar 1 secured a prompt. Pillar 2 secured a tool call. Pillar 3 secures a
**loop**, and the loop changes the threat model in one sentence: *state carries
between steps.* A goal set once influences every future step. A note written to
memory is read back later. A permission granted broadly is available on every
turn. That persistence is what makes agents powerful and what makes them
dangerous — an attacker who lands one poisoned input early gets compounding
leverage over the whole run. The fix is not a sterner prompt. It is to make the
loop's state trustworthy: lock the goal, guard what enters memory, bound how
long the loop runs, scope what each tool can do, and put a human in front of the
actions you can't take back.

## > COST SAFETY

The abuse harness (`attack/agentattack.py`) runs against a MOCK agent and MOCK
tools — hijacking the goal, poisoning memory, or firing `transfer_funds` costs
nothing and touches nothing real. `scan/scan.py --selftest`,
`guard/agentguard.py --selftest`, and `fix/fix.py --selftest` prove the logic
offline with no AWS. The only billable infrastructure is whatever your real
agent runtime uses; the loop controls themselves are code and IAM. Tear down at
session end.

## The loop (exact commands)

```
terraform apply -var-file=baseline.tfvars      # 1. deploy the naked agent
python3 scan/scan.py                            # 2. scan: 6 gaps
python3 attack/agentattack.py                   # 3. attack + review logs: 5/5
terraform apply -var-file=hardened.tfvars       # 4. harden (or fix.py)
python3 scan/scan.py                            # 5. scan again: PASS
python3 attack/agentattack.py --guarded         # 6. attack + review logs: 0/5
```

See **HARDEN.md** for the control-by-control map and **HOMEWORK.md** for the
week's assignment and the two required log reviews.

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
