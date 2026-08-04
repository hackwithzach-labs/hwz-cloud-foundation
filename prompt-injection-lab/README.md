# Prompt Injection Lab — Build it, Release it, Break it, Harden it

A tiny, real AI support agent you can **break with one message** and then
**harden with architecture** until the exact same attack does nothing. This is
the hands-on version of prompt injection — LLM01, the number one risk in the
OWASP Top 10 for LLM Applications — run through the full engineering loop.

This lab ships with the **Cloud and AI Security Engineer** course. Every project
in the course runs this same loop on real cloud infrastructure.
→ https://hackwithzach.com/foundations-course

Cybersecurity Education That Gets You Hired, Promoted and Paid.

---

## What's in here

```
agent_vulnerable.py   the ~40-line support agent, before hardening
agent_hardened.py     the same agent, with four layers of defense in depth
model.py              one model layer, three backends (sim / anthropic / bedrock)
ticket_loader.py      loads a ticket from a .txt OR a .pdf
data/accounts.json    a fake account store (the "secret" is a fake API key)
tickets/clean_ticket.txt      a normal customer ticket
tickets/poisoned_ticket.txt   the indirect prompt-injection attack, as text
tickets/poisoned_ticket.pdf   the same attack hidden inside a PDF attachment
tools/make_poisoned_pdf.py    regenerate the poisoned PDF (needs reportlab)
logs/detections.log   written by the hardened agent when it catches an attack
```

## Setup — pick a backend

**Fastest: offline simulation (no key, no cloud).** Runs instantly. It mimics
how an LLM blindly follows instructions hidden in its input, so the leak and the
block are deterministic and repeatable. Great for a first run and for recording.

```
python agent_vulnerable.py tickets/clean_ticket.txt
```

**Real model — Anthropic API** (one key):

```
pip install anthropic
export HWZ_BACKEND=anthropic
export ANTHROPIC_API_KEY=sk-ant-...
```

**Real model — AWS Bedrock** (the course stack; log in first, no stored keys):

```
pip install boto3
aws sso login                 # short-lived creds, nothing stored on disk
export HWZ_BACKEND=bedrock
export AWS_REGION=us-east-1
```

## Run the loop

```
# 1. BUILD + RELEASE — a normal ticket works
python agent_vulnerable.py tickets/clean_ticket.txt

# 2. BREAK — one poisoned ticket, no code changes, and it leaks a secret
python agent_vulnerable.py tickets/poisoned_ticket.txt

# 3. HARDEN — same attacker, same ticket, dead on arrival
python agent_hardened.py tickets/poisoned_ticket.txt

# 4. and the hardened agent still serves real customers
python agent_hardened.py tickets/clean_ticket.txt
```

Same attack, hidden in a PDF instead of pasted text (needs `pip install pypdf`):

```
python agent_vulnerable.py tickets/poisoned_ticket.pdf   # leaks
python agent_hardened.py   tickets/poisoned_ticket.pdf   # blocked
```

This is the scary delivery: the injection rides inside a document your agent is
asked to read. Regenerate or edit the PDF with `python tools/make_poisoned_pdf.py`
(needs `pip install reportlab`).

## Why it breaks

In `agent_vulnerable.py`, the stranger's ticket text is dropped into the **same
channel** as your instructions. To the model, your rules and their text are the
same kind of thing. The attacker's instruction comes last, so it wins. You
**cannot prompt your way out of this** — a sterner system prompt still leaks.

## Why the fix holds — four layers, none of them a prompt

1. **Separate instructions from data.** Untrusted text goes behind a boundary,
   labeled as data to analyze, never instructions to follow. Stops lazy attacks;
   we assume it can be bypassed and do not rely on it.
2. **Least privilege at the tool.** The lookup tool is bound to the authenticated
   session identity. Ask it for someone else's account and it says no, in code,
   every time. **The model is not a security boundary. Your code is.**
3. **Output filter.** No secret leaves, ever — the reply is scanned and blocked
   before it reaches a human, no matter what the model decided to say.
4. **Log and detect.** Every tool call is logged; a cross-account attempt raises
   an event. Getting attacked is not an *if* — the question is whether you see it.

## A note on use

This is a defensive teaching lab. The "target" is a toy agent you run on your own
machine, the account store is fake, and the "secret" is a made-up string. Use it
to learn how to build agents that don't leak. That's the job.

**Attack only what you own.** The same PDF trick works against any assistant that
reads uploaded files, including hosted ones. If you want to see indirect injection
on a hosted assistant, do it only inside your own account, with your own harmless
content, and strictly within that provider's Terms of Service and usage policies.
Do not use these techniques against other people's systems, other users' data, or
to get a service to break its own rules. This lab exists to help you build the
defenses, not to attack anyone.

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are
trademarks of Vigilantia Technologies INC.
