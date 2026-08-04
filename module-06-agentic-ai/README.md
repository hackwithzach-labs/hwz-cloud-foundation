# Module 6 — Agentic AI (Pillar 3): securing the loop

The code behind **Chapter 13**. Pillar 2 secured a single tool call. Pillar 3
secures a **loop**: an agent that chains many tool calls toward a goal, carrying
a memory between steps. Deploy it naked and watch it get its goal hijacked
mid-run, obey a poisoned note left in its own memory, loop until the bill hurts,
and chain small steps into one irreversible action with no human in the way —
then lock every one of those doors.

```
scan/scan.py          hwz-scan for the agent loop: 6 gaps naked, PASS locked
guard/agentguard.py   the loop guardrail (goal lock, memory, step budget, human gate)
attack/agentattack.py mock-safe agent-abuse harness: 5/5 -> 0/5 guarded
fix/fix.py            hwz-harden: lock the loop (+ offline --selftest)
foundation/           Terraform: per-tool least-privilege roles + the 6 flags
  modules/agent/      scoped per-tool roles (least priv) vs one broad shared role
  baseline.tfvars     all six controls off
  hardened.tfvars     all six on
TEACH.md HARDEN.md HOMEWORK.md LESSON.md   the chapter, the control map, the work
```

## The loop

```
terraform apply -var-file=baseline.tfvars    # deploy the naked agent
python3 scan/scan.py                          # 6 gaps
python3 attack/agentattack.py                 # 5/5 abuses succeed
python3 fix/fix.py                             # harden (or -var-file=hardened.tfvars)
python3 scan/scan.py                          # PASS
python3 attack/agentattack.py --guarded       # 0/5
python3 guard/agentguard.py --selftest         # goal/memory/budget/human all proven
python3 fix/fix.py --selftest                  # 6 gaps -> 0, no AWS
```

## The four loop-only risks (beyond Pillar 2)

1. **Goal hijacking** — a poisoned observation replaces the agent's objective.
   Hijack the goal once and every later step serves the attacker.
2. **Memory poisoning** — a note written to memory fires on a *later* step.
   Indirect injection with a delay fuse.
3. **Runaway loops** — no step budget means unlimited cost and unlimited
   attacker attempts.
4. **Cascading agency** — a chain of individually-small actions adds up to one
   irreversible one, with no human gate.

## What gets hardened, and where

See **HARDEN.md** for the full control-by-control map. In short: lock the goal,
guardrail every memory write, give each tool its own least-privilege role, bound
the loop with a step budget, put a human in front of every irreversible action,
and audit every step into the Chapter 10 SOC.

Runs offline against a mock agent and mock tools by default — **attack only what
you own.**

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
