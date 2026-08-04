# HARDEN — Module 4: LLM Security (Pillar 1)

What gets hardened, control by control, where it deploys, and the exact attack
it stops. A security lab that does not name what each defense stops and where it
sits is a demo, not a lesson. This is the table the chapter, the scanner, and
this doc all agree on.

| # | Control | Where it deploys | What it hardens | Maps to |
|---|---|---|---|---|
| 1 | WAF managed rule group (`AWSManagedRulesCommonRuleSet` + Known Bad Inputs) | API edge — WAF web ACL on the ALB / API Gateway | Command injection, XSS, path traversal, known-bad inputs, bad bots | CWE-77 / CWE-79, OWASP Web |
| 2 | WAF rate-based rule (2000 / 5 min / IP) | API edge — WAF web ACL | Volumetric floods and scanners, before they become tokens and cost | LLM10 |
| 3 | Input guardrail on the user prompt | `guard.input_guardrail()`, before the model call | Direct ingress injection typed into the prompt | LLM01 |
| 4 | Input guardrail on ingested content | `guard.input_guardrail(src)` on every retrieved / uploaded doc | Indirect injection buried in a ticket, PDF, RAG chunk, or web page | LLM01 |
| 5 | Instruction / data channel boundary | Prompt construction (data wrapped, labeled untrusted) | The same-channel root cause that makes indirect injection work | LLM01 |
| 6 | Output guardrail (secret / PII / system-prompt scan) | `guard.output_guardrail()`, after the reply, before egress | Secrets and customer PII leaving the model, system-prompt exfiltration | LLM02 |
| 7 | Least-privilege bound tool | Tool layer (tool bound to session identity) | Cross-account and excessive-agency actions an injection tries to trigger | LLM06 / LLM08 |
| 8 | Detection logging to the SOC | Chapter 10 alert path (WAF + guardrail logs) | Making every blocked attempt visible instead of silent | — |

Read as a sentence: **the WAF puts rules in place for command injection and XSS
at the edge; the input guardrail stops direct injection on the way in and
indirect injection hidden in ingested content; the output guardrail stops
secrets and PII on the way out; the bound tool refuses the cross-account action;
and every block is logged where detection can see it.**

## The one flag pair

Everything above is off in `baseline.tfvars` and on in `hardened.tfvars`:

```
guardrails_enabled = false -> true    # controls 3, 4, 5, 6
waf_enabled        = false -> true    # controls 1, 2 (and 8 via WAF logs)
```

Control 7 (the bound tool) is architecture in the app itself — see the shared
indirect-injection lab (`prompt-injection-lab/`), Layer 2 — and is on in the
hardened agent regardless of flag.

## Prove it

```
# naked
terraform apply -var-file=baseline.tfvars
python3 scan/scan.py            # NAKED. 5 gaps
python3 attack/inject.py        # 6/6 injections succeed
python3 guard/guard.py --selftest   # filters proven offline (still green)

# hardened
terraform apply -var-file=hardened.tfvars   # or: python3 fix/fix.py
python3 scan/scan.py            # PASS
python3 attack/inject.py --guarded          # 0/6 injections succeed
```

## Why none of the fixes is a better prompt

Every control here is architecture, not persuasion. You cannot prompt your way
out of injection: the model has no reliable way to tell your rules from text
shaped like rules, so a sterner system prompt still loses. The guardrail filters
content the model never gets to misjudge, the boundary marks data as data, the
bound tool refuses in code, and the output filter catches the result even when
the method was novel. The WAF, meanwhile, never sees meaning at all — it kills
the structural and volumetric noise the guardrail would waste tokens reading.
Each is blind to what the others catch. You run all of them.

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
