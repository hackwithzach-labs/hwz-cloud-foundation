# Week 2 homework: the API layer

You did the loop with me in the runbook. Now do it on your own and produce the
evidence. This is a cohort co-build week: run it, post your artifacts in the
build-along channel, and bring any gap where the real output differs from what
TEACH.md or RUNBOOK.md said to expect.

## Deliverables (five artifacts, same shape as Module 1)

1. `evidence/01-attack-weak.txt` the attack output against the baseline app,
   showing A1 A2 A3 SUCCEEDED.
2. `evidence/02-logs-weak.md` your note on the weak log: what you could NOT
   learn from `got a request at <time>`.
3. `evidence/03-attack-hardened.txt` the same attacks against the hardened app,
   all BLOCKED, exit 0.
4. `evidence/04-logs-hardened.md` the structured audit line for the ghost
   request, pasted, with one sentence on why it is enough for an investigator.
5. `evidence/05-selftest.txt` the `--selftest` output, proving you can verify
   the logic with zero cost.

## Stretch (for the ones who want the interview edge)

- Point the app at a real Bedrock model behind the endpoint the Terraform root
  creates. Run one real completion, then `terraform destroy`. Capture the bill.
- Add a fifth control: an allowlist of models the API may call, and an attack
  that requests a model not on the list. Wire it the same way, a flag plus a
  judge in the attack script.

## The rule that carries forward

Every control you added maps to an attack you ran and an OWASP item you can
name. That triple, control plus attack plus framework name, is the sentence
that wins the interview. Write one for each of the four before next week.

© 2026 Vigilantia Technologies INC. All rights reserved.
