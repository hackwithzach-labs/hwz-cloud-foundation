# Chapter 9 — API Security (visual lab)

Four controls as cards, proved by firing the four attacks at your **running
API** and reading `attack.py`'s own verdicts.

```powershell
# terminal 1 — the API, weak
$env:HWZ_PROFILE="baseline"
python -m uvicorn app.main:app --port 8000

# terminal 2 — the lab
pip install -r requirements.txt
python app.py                     # http://localhost:5109
```

Then flip the profile, restart the API, and refresh this page:

```powershell
$env:HWZ_PROFILE="hardened"
python -m uvicorn app.main:app --port 8000
```

Every card goes green without one line of code changing. That is the chapter.

## The rule this lab obeys

Module 2 has no scanner, because its weak/hardened switch is not in the cloud —
it is `HWZ_PROFILE` in the app process. So `apiprobe.py` gives this chapter the
same `collect_live()` / `run_checks()` pair every other module has, and it
**imports `attack.py`'s judges rather than copying them**:

```python
sys.path.insert(0, str(HERE.parent / "attack"))
import attack
snap["verify-audience"] = attack.judge_wrong_audience(r.status_code)
```

The probe performs the HTTP calls. Every pass/fail decision stays in the CLI's
own code. If a judge changes tomorrow, this changes with it.

## If the API is not running

You get one finding that tells you exactly what to start, rather than four
confusing timeouts. Fail fast and say why.

## A4 and the honest caveat

The structured-audit control is definitively proved by a JSON line in the
server's **stderr**, which a browser cannot read. The card derives its state
from the profile the app reports on `/health` and says on its face that stderr
is the real proof. A lab that overstates what it verified is the exact failure
this course teaches you to catch.

Terminal equivalent: `python attack/attack.py --url http://localhost:8000`

© 2026 Vigilantia Technologies INC. ™ HackWithZach.
