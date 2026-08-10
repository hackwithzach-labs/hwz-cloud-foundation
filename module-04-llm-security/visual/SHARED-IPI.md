# The Shared Indirect-Prompt-Injection Lab

This lab is the canonical indirect-injection (IPI) exercise for the whole course.
Rather than write a fresh injection lab into every pillar, each LLM and Agentic
module **references this one**. It is the poisoned-document → agent-ingests →
harden-with-architecture story, run through the locked four-step course loop.

## Who uses it

- **Pillar 1 — LLM Security (Module 4 / Chapter 11).** The indirect half of
  LLM01: a poisoned ticket/PDF/RAG chunk the model reads as data. The guardrail
  (input filter on every ingested source + output filter) is layered on top of
  this lab's four architectural defenses.
- **Pillar 3 — Agentic AI.** Where indirect injection is most dangerous, because
  the agent *acts* on what it reads. This lab is the base; the agentic module
  adds real tool calls with consequences and the tool-call guardrail.
- **Pillars 2 and 4** reference the same pattern for poisoned tool descriptions /
  API responses (MCP) and poisoned dependencies / comments (vibe coding).

## Four-step conformance (new)

The lab now carries `ipi_scan.py`, which brings it into the same
deploy → **scan** → harden → **scan** shape as every other module:

```
python3 ipi_scan.py agent_vulnerable.py   # VULNERABLE — 4 missing layers
python3 ipi_scan.py agent_hardened.py     # PASS — all four layers present
python3 ipi_scan.py --selftest            # offline proof (vulnerable=4, hardened=0)
```

The four layers it checks are the ones the hardened agent already implements:

1. **Channel boundary** — untrusted text wrapped and labeled as data, not
   instructions.
2. **Bound tool** — the lookup is bound to the session identity, so a
   cross-account request is refused in code. *The model is not a security
   boundary. Your code is.*
3. **Output filter** — no secret leaves the reply, no matter what the model says.
4. **Detection log** — every tool call and cross-account attempt is logged.

## The through-line

Direct injection you can filter at the door. Indirect injection rides inside
content the model was asked to read, so you filter every ingested source and back
it with architecture that assumes a payload got through. This lab is where that
lesson is felt; the guardrail in Module 4 is where it is systematized; every
later pillar reuses both.

**Attack only what you own.** See this lab's README, "A note on use."

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
