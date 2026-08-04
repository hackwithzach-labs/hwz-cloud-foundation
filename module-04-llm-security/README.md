# Module 4 — LLM Security (Pillar 1): Guardrails and the WAF for AI

The code behind **Chapter 11**. Deploy an authenticated, schema-clean inference
API that still obeys a stranger's buried instruction and leaks a secret — then
stop it with two firewalls: a **guardrail** that reads meaning and a **WAF** that
reads structure. Neither replaces the other.

```
guard/guard.py        input + output guardrail (LLM01/LLM02), offline --selftest
scan/scan.py          hwz-scan for the LLM layer: 5 gaps naked, PASS hardened
attack/inject.py      mock-safe injection harness: direct + indirect, 6/6 -> 0/6
fix/fix.py            hwz-harden: turn both firewalls on (live-account partner)
foundation/           Terraform: WAF web ACL (managed rules + rate cap) + flags
  modules/waf/        the aws_wafv2_web_acl, gated on waf_enabled
  baseline.tfvars     guardrails_enabled=false, waf_enabled=false
  hardened.tfvars     both true
TEACH.md HARDEN.md HOMEWORK.md LESSON.md   the chapter, the control map, the work
```

## The loop

```
terraform apply -var-file=baseline.tfvars   # deploy naked
python3 scan/scan.py                         # 5 gaps
python3 attack/inject.py                      # 6/6 injections succeed
python3 fix/fix.py                            # harden (or: -var-file=hardened.tfvars)
python3 scan/scan.py                         # PASS
python3 attack/inject.py --guarded            # 0/6
python3 guard/guard.py --selftest             # filters proven offline
```

## What gets hardened, and where

See **HARDEN.md** for the full control-by-control map. In short: the WAF stops
command injection and XSS at the edge; the input guardrail stops direct injection
and indirect injection hidden in ingested content; the output guardrail stops
secrets and PII leaving the model; the bound tool refuses cross-account actions;
every block is logged into the Chapter 10 SOC.

## Indirect injection

The shared indirect-injection lab lives in `prompt-injection-lab/` and is the one
every LLM and Agentic pillar builds on. A poisoned document the agent is asked to
read, hardened with four architectural layers.

Runs offline against a mock model by default — **attack only what you own.**

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
