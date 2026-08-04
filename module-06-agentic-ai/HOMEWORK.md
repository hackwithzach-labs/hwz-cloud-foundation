# HOMEWORK — Module 6: Agentic AI (Pillar 3)

## Build

1. Deploy the naked agent (`terraform apply -var-file=baseline.tfvars`).
2. Run `scan/scan.py` and paste the 6-gap output.
3. Run `attack/agentattack.py` — confirm 5/5 abuses succeed (goal hijacked,
   poisoned memory fires, loop runs away, cascade reaches `delete_all`,
   `transfer_funds` executes with no human). **Log review #1 (naked).**
4. Harden (`terraform apply -var-file=hardened.tfvars` or `fix/fix.py`).
5. `scan/scan.py` → PASS. `attack/agentattack.py --guarded` → 0/5, and note which
   lock stopped each one. **Log review #2 (locked).**
6. Confirm the blocked steps show up in your Module 3 detection pipeline.
7. Tear down.

## Prove your guardrail (offline, no cost)

- Run `guard/agentguard.py --selftest`: 6 hijacks blocked / 5 legit steps
  allowed, 4 poisoned notes blocked / 3 legit notes allowed, 5 dangerous actions
  gated / 4 safe actions auto-run, step budget enforced.
- Run `fix/fix.py --selftest`: 6 gaps → 0.
- Add one new goal-hijack phrasing of your own and one new legitimate step
  input. If the legit one gets blocked, tune `GOAL_OVERRIDE` until it passes
  without letting your new hijack through. This is the false-positive / false-
  negative tradeoff every real guardrail lives with.

## Observability and log review

Run the standard observability homework from the end of the chapter, in both
states. For this module, watch specifically for **agentic** signals: a run that
hits the step budget (a bounded loop that would otherwise be unbounded), a tool
call an agent role was denied (least privilege earning its keep across the
chain), and an action parked in the approval queue instead of firing. Set the
metric filter, trip it, and confirm the alarm fires in the locked state where it
was silent in the naked one.

## Turn in

Your repo with: the two scan outputs, the two attack outputs, the two log
reviews, your extended `agentguard.py` fixtures, and a one-paragraph answer to:
"Why is an agent loop more dangerous than a single tool call, and what does each
of the six locks stop?"

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
