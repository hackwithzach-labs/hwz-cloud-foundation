# Module 8 — Capstone (Chapter 15)

All four pillars, one stack, one payload. This is the module you put in front
of a hiring manager.

```
foundation/         the only root that composes everything at once
attack/end_to_end.py  one poisoned ticket through five gates
attack/tickets/     the same attack as .txt and as .pdf
scan/scan.py        every pillar in one report, plus the green wall
visual/app.py       the browser version, port 5115
```

## The loop

```bash
# 0. prove everything first — offline, no AWS, no cost
python3 scan/scan.py --green-wall

# 1. BUILD IT WEAK
cd foundation
terraform init
terraform apply -var-file=baseline.tfvars

# 2. SCAN — every pillar, one report
cd .. && python3 scan/scan.py --posture foundation/posture.json

# 3. BREAK IT — the poisoned ticket, through the real chain
python3 attack/end_to_end.py --ticket attack/tickets/poisoned.pdf \
    --posture foundation/posture.json
#    -> BREACH. Five gates, all open, and the SOC never hears about it.

# 4. HARDEN IT
cd foundation && terraform apply -var-file=hardened.tfvars && cd ..

# 5. SAME ATTACK, SAME PAYLOAD
python3 attack/end_to_end.py --ticket attack/tickets/poisoned.pdf \
    --posture foundation/posture.json
#    -> BLOCKED at the first lock, and this time the SOC saw it.

# 6. SCAN AGAIN
python3 scan/scan.py --posture foundation/posture.json    # PASS

# 7. the browser version of all of it
cd visual && pip install -r requirements.txt && python3 app.py   # :5115
```

Then **tear it down the same day.** Chapter 15 ends with the full sweep. This
is the highest hourly cost in the course because every hourly resource you have
met is standing at once.

## Three things this module does that are worth stealing

**The posture file is the contract.** `terraform apply` writes
`foundation/posture.json`, and both the attack and the visual lab read that
file rather than the tfvars. The attack therefore reflects what you *deployed*,
not what you *intended*. If you edit hardened.tfvars and forget to apply, the
attack still reports the old posture — which is the correct and useful
behaviour.

**The book's strongest claim is tested, not asserted.** Chapter 15 says it
"would not have mattered which lock you removed." That is easy to write and
easy to be wrong about, so:

```bash
python3 attack/end_to_end.py --prove-independence
```

runs the chain once per lock with that lock ON and every other lock OFF. All
four preventive locks must hold alone or it prints FAIL. Defense in depth means
four independent locks, not one lock and three spectators.

**run-audit is counted honestly.** It is detection, not prevention. It is why
you find out, not why it did not happen — and `--prove-independence` shows it
failing to stop the chain on purpose. A capstone that counted it as a fourth
lock would teach students to overcount their defenses, which is its own kind of
breach.

## The green wall

```bash
python3 scan/scan.py --green-wall
```

Runs every module's offline `--selftest` in sequence: eleven proofs, no AWS, no
credentials, no cost. Anyone can clone the repo and watch it pass on their own
laptop, which is a far stronger claim than a screenshot of your console.

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are
trademarks of Vigilantia Technologies INC.
