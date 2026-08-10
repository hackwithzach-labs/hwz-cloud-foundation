# Chapter 15 — Capstone visual lab

```bash
pip install -r requirements.txt
python app.py            # http://localhost:5115
```

Port is `5100 + chapter`, like every visual lab here.

Flip **Profile** between `baseline.tfvars` and `hardened.tfvars` and watch the
same poisoned ticket go from BREACH to BLOCKED. Flip **Ticket** to Clean and
confirm the hardened stack still does its job — a control set that breaks the
product is not a control set anyone will keep.

The two panels on the right are the Chapter 10 lesson in one screen. **Agent
trace** is what happened. **SOC** is what reached a human. In the weak profile
the first is full and the second is empty: the events existed, the log group
filled up, and no metric filter was watching. "It was logged" and "we found
out" are two different claims, and only one of them saves you.

This console contains no logic. It imports `../attack/end_to_end.py` and
`../scan/scan.py` and renders what they return, so the browser and the terminal
cannot disagree.

© 2026 Vigilantia Technologies INC. ™ HackWithZach.
