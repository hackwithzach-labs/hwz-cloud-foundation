# Chapter 14 — Pre-Deploy Gate (visual lab)

```bash
pip install -r requirements.txt
python app.py            # http://localhost:5114
```

Port is `5100 + chapter`, like every visual lab in this course.

## What it shows

Two builds of the same request. **AI output, unedited** fails the gate with six
findings and exit code 1. **Same ask + control map** passes with exit code 0.
Each view shows the generated Terraform and the exact prompt that produced it,
so the cause and the effect are on one screen.

## The rule this lab obeys

It contains no checks. It imports this module's own gate, which imports the
Chapter 8 scanner:

```python
sys.path.insert(0, str(MODULE_DIR / "scan"))
import scan as gate
findings = gate.run_artifact_checks(gate.load_ch8(), snapshot)
```

Three layers, one definition of "secure". The browser and the terminal cannot
disagree, because there is only one thing to disagree with.

## No LIVE/FIXTURE badge here

Every other console in this course carries one, because every other console can
read a real account and must never let a sample pass itself off as your
infrastructure. This pillar has no account by design — the artifact has not
been applied yet, and that is the entire point — so there is nothing for the
badge to distinguish.

Terminal equivalent: `python scan/scan.py --snapshot scan/fixtures/ai-generated-insecure.json`

© 2026 Vigilantia Technologies INC. ™ HackWithZach.
