# LESSON — Module 6: Agentic AI (Pillar 3)

The code, explained.

## `guard/agentguard.py` — the loop guardrail

Four pure functions, one per loop-only risk. `goal_lock(original_goal, step_text)`
refuses any step input that tries to replace the objective — this is the single
most dangerous agentic failure, because a hijacked goal turns every later step
against you. `memory_guardrail(note)` vets everything written to memory, because
memory is read back on a later step: a poisoned note is indirect injection with a
delay fuse. `step_budget_ok(step_index, budget)` bounds the loop. `requires_human
(action, args)` returns True for the actions you can't take back, so the loop
halts for a person instead of firing autonomously. `--selftest` proves all four
against injected and legitimate fixtures — and note the two failures it caught
during development (a hijack phrasing that slipped the regex, a legit note about
a "password reset" wrongly flagged): that false-positive / false-negative tension
is the real work of running a guardrail, and the selftest is where you feel it.

## `scan/scan.py` — hwz-scan for the agent loop

Same split as every scanner: `collect_live()` reads the posture the Terraform
emits, `run_checks()` judges it. Six checks map to the six controls. `--selftest`
proves naked → 6 and locked → 0 with no AWS.

## `attack/agentattack.py` — the abuse harness (mock-safe)

A tiny `MockAgent` with `observe`, `remember`, `step`, and `act`. Five abuses run
against it: goal-hijack, memory-poison, runaway-loop, cascading-agency, and
unreviewed-destructive. Naked → 5/5. `--guarded` wires `agentguard` into each of
the four decision points → 0/5, each dying at a different lock. The agent and its
tools are mocks, so nothing here spends a dollar or touches a real account.

## `foundation/` — the Terraform

`modules/agent/` is the one control here that is pure infrastructure: when
`tool_least_priv` is on, each tool the agent can call gets its OWN scoped role
(research reads one table; notify calls SES only); when off, the whole loop runs
under one broad role with `dynamodb:*`, `ses:*`, `s3:*`, `secretsmanager:*`,
`lambda:*` — the weak default the scanner flags. The other five controls live in
the agent runtime, so the root emits a posture file the scanner reads, keeping
the deploy → scan → attack → harden → scan loop honest end to end.

## `fix/fix.py` — hwz-harden

The live-account partner: locks the loop and records the posture. `--selftest`
proves, with no AWS, that the posture it writes takes the scanner to zero.

## Where it plugs in

This is the top of the stack. It composes the Chapter 8 foundation, the Chapter 9
API, and the Chapter 12 MCP + tools, all pinned hardened, and adds the loop on
top. The shared indirect-injection lab from Chapter 11 delivers its payload here
through a poisoned observation or a poisoned memory note. Every blocked step,
every parked approval, and every budget stop logs into the Chapter 10 SOC — which
is why the capstone in Chapter 15 can ask you to catch an agentic attack end to
end, from the poisoned input to the alarm.

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
