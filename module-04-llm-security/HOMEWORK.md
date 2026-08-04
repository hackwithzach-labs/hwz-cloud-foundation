# HOMEWORK — Module 4: LLM Security (Pillar 1)

Two live calls this week: on the first, we teach the concept and walk the loop;
you go build. On the second, Q&A. Deliverables below go in your course repo.

## Build

1. Deploy the naked profile (`terraform apply -var-file=baseline.tfvars`).
2. Run `scan/scan.py` and paste the 5-gap output into your notes.
3. Run `attack/inject.py` and confirm 6/6 injections succeed — direct AND
   indirect. Open the app log and screenshot the recorded-but-unstopped attempts.
   **This is log review #1 (weak state).**
4. Harden (`terraform apply -var-file=hardened.tfvars` or `fix/fix.py`).
5. Run `scan/scan.py` again — PASS. Run `attack/inject.py --guarded` — 0/6.
6. Confirm the guardrail/WAF blocks show up in your Module 3 detection pipeline.
   **This is log review #2 (hardened state).**
7. Tear down.

## Prove your filter (offline, no cost)

- Run `guard/guard.py --selftest`. It must be green: all injection fixtures
  blocked, all benign fixtures allowed, all leak fixtures caught.
- Add **one** new injection fixture and **one** new benign fixture of your own.
  If your new benign prompt gets blocked, tune the filter until it passes without
  letting any injection through. A guardrail that blocks everything is as useless
  as one that blocks nothing — prove yours does neither.

## Indirect-injection lab (shared)

- In `prompt-injection-lab/`, run the poisoned **PDF** ticket through the
  vulnerable agent (it leaks) and the hardened agent (it is blocked). Name which
  of the four layers stopped it, and why the fix is architecture, not a prompt.

## Turn in

Your repo, with: the two scan outputs, the two attack outputs, the two log
reviews, your extended `guard.py` fixtures, and a one-paragraph answer to:
"Why does an AI API need both a guardrail and a WAF, and what does each catch
that the other cannot?"

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
