# Chapter 13 — Agent Loop (visual lab)

The browser layer on top of this chapter's CLI lab.

```bash
pip install -r requirements.txt
python app.py            # http://localhost:5113
```

Port is `5100 + chapter`, so no visual lab in the course collides with another.

## The rule this lab obeys

It contains no checks and does not talk to AWS itself. It imports this module's
own scanner and renders what it returns:

```python
sys.path.insert(0, str(APP_DIR.parent / "scan"))
import scan as scanner
snap = scanner.collect_live(project, region)
gaps = scanner.run_checks(snap)
```

One scanner, two renderings. The browser and the terminal cannot disagree,
because there is only one thing to disagree with.

## Three card states

**PRESENT** green, **MISSING** red, and **UNTESTED** amber. A check that could
not run — because nothing upstream exists for it to evaluate — is amber, never
green. No findings is not the same fact as no problems, and a dashboard that
cannot tell you the difference is how audits get faked.

## Where the data comes from

Wherever you deployed. A green **LIVE** badge means it read your real stack, so
`terraform apply` and `terraform destroy` change this page on refresh. An amber
**FIXTURE** badge means it fell back to the bundled sample, with the reason on
screen, so a simulation can never pass as your account.

Terminal equivalent: `python scan/scan.py --project hwz --region us-east-1`

## The other half of this chapter

This console shows the *cloud* posture of the agent stack. The behaviour half —
an agent reading a poisoned document and acting on what it read — is the shared
indirect-injection lab, which lives with Chapter 11:

```bash
cd ../../module-04-llm-security/visual
python app.py            # http://localhost:5111
```

Agentic AI is where indirect injection does the most damage, because the agent
does not just *say* something wrong, it *does* something wrong. Run the
Vulnerable build against the poisoned ticket, then the Hardened build against
the same ticket, and notice that what saved you was a tool bound to the session
identity — code, not a better prompt. Then come back here and confirm the same
idea holds in the cloud: the agent's execution role scoped to exactly what it
needs and nothing more.

`../../module-04-llm-security/visual/SHARED-IPI.md` explains how all four pillars share
that one lab.

© 2026 Vigilantia Technologies INC. ™ HackWithZach.
