# HARDEN — Module 6: Agentic AI (Pillar 3)

What gets hardened, control by control, the door it locks, and the risk it maps
to. Each row is one gap the scanner flags and one lock the harden pass closes.

| # | Control | Where it deploys | What it hardens | Maps to |
|---|---|---|---|---|
| 1 | Goal lock | Agent runtime (system goal held outside model-editable context) | Goal hijacking — injected content cannot redirect the run mid-loop | LLM01 |
| 2 | Memory guardrail | Every write to agent memory / scratchpad | Poisoned notes that fire on a later step (delayed indirect injection) | LLM01 / LLM08 |
| 3 | Per-tool least privilege | Each tool's own IAM role (Terraform) | Excessive agency compounding across a chain — one hijacked step can't do everything | LLM06 |
| 4 | Step budget | Orchestrator (per-run step/tool-call cap) | Runaway loops — cost/DoS and unlimited attacker attempts | LLM06 / DoS |
| 5 | Human-in-the-loop approval | Before any high-impact/irreversible action | Autonomous delete/pay/send/disable with no person in the way | LLM06 / LLM02 |
| 6 | Run audit | Chapter 10 SOC (every step + decision logged) | Invisible autonomous abuse after the fact | — |

Read it as a sentence: **the goal is locked so it can't be rewritten, every
memory write is vetted, each tool holds only its own privilege, the loop is
bounded, a human gates every irreversible action, and every step is logged where
detection can see it.**

## The flags

Everything above is off in `baseline.tfvars` and on in `hardened.tfvars`:

```
goal_locked      = false -> true   # control 1
memory_guardrail = false -> true   # control 2
tool_least_priv  = false -> true   # control 3 (the one that is pure IAM)
step_budget      = false -> true   # control 4
hitl_approval    = false -> true   # control 5
run_audit        = false -> true   # control 6
```

## Prove it

```
# naked
terraform apply -var-file=baseline.tfvars
python3 scan/scan.py                     # NAKED. 6 gaps
python3 attack/agentattack.py            # 5/5 abuses succeed
python3 guard/agentguard.py --selftest    # filters proven offline (green)

# locked
terraform apply -var-file=hardened.tfvars    # or: python3 fix/fix.py
python3 scan/scan.py                     # PASS
python3 attack/agentattack.py --guarded      # 0/5 — each dies at a different lock
```

Every abuse dies somewhere different: the hijack at the goal lock; the poisoned
memory at the write guardrail; the runaway loop at the step budget; the cascade
at least-privilege *and* the human gate; the destructive call at the human gate.
No single control is load-bearing — that is defense in depth you can point at.

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
