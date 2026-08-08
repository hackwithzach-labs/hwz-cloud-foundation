# Chapter 10 — SOC Console (visual lab)

The browser layer on top of the Chapter 10 CLI lab. Eight detection surfaces as
cards, the chain from event to human drawn out, and a **BLIND / WIRED** verdict.

```bash
pip install flask boto3
python app.py            # http://localhost:5110
```

Port is `5100 + chapter`, so every visual lab in the course has its own and
nothing collides: Ch8 → 5108, Ch10 → 5110, Ch13 → 5113, Lab Console → 5116.

## The rule this lab obeys

It does not talk to AWS and it does not reimplement a single check. It imports
`../detect/detect.py` and calls the same functions your terminal run calls:

```python
snap     = detect.collect_live(project, region)
findings = detect.run_checks(snap)
```

There is exactly **one scanner**. This page is a second rendering of it, never a
second opinion. If the browser and the terminal could disagree, you would stop
trusting both.

## Where the data comes from

Wherever you deployed. `collect_live()` reads your live account, so
`terraform apply` and `terraform destroy` change this screen. The header shows a
green **LIVE** badge and your account number when it is reading you for real.

With no credentials, or with a read that fails, it falls back to the bundled
fixtures in `../detect/fixtures/` — the same ones `detect.py --selftest` judges
— and shows an amber **FIXTURE** badge plus the reason. A simulation can never
be mistaken for your account.

The two buttons marked *(fixture)* force the blind and wired fixtures on
purpose, which is what you want on camera when the account is mid-apply.

## Suggested run order

1. `terraform apply -var-file=baseline.tfvars` — the account goes blind
2. `python attack/emit.py` — evidence is now written down
3. Open this page → **BLIND**, 9 gaps, 5 HIGH
4. `terraform apply -var-file=hardened.tfvars` — the SOC comes up
5. `python attack/emit.py` again — filters only count what arrives *after* they exist
6. Refresh → **WIRED**

Terminal equivalent at any point:

```bash
python detect/detect.py --project hwz --region us-east-1
```

© 2026 Vigilantia Technologies INC. ™ HackWithZach. Education and defense only.
