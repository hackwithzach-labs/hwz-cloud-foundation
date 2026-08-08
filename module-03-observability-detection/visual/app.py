#!/usr/bin/env python3
"""
app.py — the Observability & Detection Lab, as a live SOC console.

Chapter 10's visual layer. A black/red/white SOC wall you run locally in the
browser: the eight detection surfaces as cards, the chain from event to human
drawn out, and a BLIND / WIRED verdict that changes when you change your
account.

THE RULE THIS FILE OBEYS
------------------------
This app does not talk to AWS. It does not reimplement a single check. It
imports ../detect/detect.py and calls the SAME functions your CLI run calls:

    snap     = detect.collect_live(project, region)
    findings = detect.run_checks(snap)

That is deliberate and it is the whole integrity guarantee of the visual labs.
If the browser and the terminal could disagree, a student would stop trusting
both. There is exactly one scanner; this is a second rendering of it.

WHERE THE DATA COMES FROM
-------------------------
Wherever you deployed. detect.collect_live() reads your live account through
boto3, so `terraform apply` changes this screen. If no credentials are present
or nothing is deployed, the app falls back to the bundled fixtures and says so
in a banner, so a simulation can never be mistaken for your account.

    pip install flask boto3
    python app.py               # then open http://localhost:5110

(c) 2026 Vigilantia Technologies INC. TM HackWithZach. Education/defense only.
"""
import json
import os
import sys
import traceback
from pathlib import Path

from flask import Flask, Response, jsonify, request

APP_DIR = Path(__file__).resolve().parent

# Import the module's own scanner. Same file the CLI runs. No second copy.
sys.path.insert(0, str(APP_DIR.parent / "detect"))
import detect  # noqa: E402

PORT = int(os.environ.get("PORT", "5110"))
PROJECT = os.environ.get("HWZ_PROJECT", "hwz")
REGION = os.environ.get("AWS_REGION", "us-east-1")

app = Flask(__name__)

# --------------------------------------------------------------------------
# The eight surfaces, in chain order. Each card names the link it represents,
# so the wall reads as one path from "it happened" to "a human knows" rather
# than as eight unrelated AWS services.
# --------------------------------------------------------------------------
SURFACES = [
    {"key": "cw-filter", "name": "Metric Filters",
     "chain": "log line -> number", "why": "Turns text in the log group into a metric CloudWatch can alarm on. No filter, no arithmetic, and the evidence just accumulates."},
    {"key": "cw-alarm", "name": "Alarms",
     "chain": "number -> threshold", "why": "Decides when a count becomes an incident. An alarm with nothing upstream is untested, not healthy."},
    {"key": "eventbridge", "name": "EventBridge Rules",
     "chain": "API call -> event", "why": "Watches the control plane. This is what notices someone turning your audit trail off."},
    {"key": "sns", "name": "Alert Path",
     "chain": "event -> a person", "why": "One topic every detection publishes to. Without it the whole chain terminates in a wall."},
    {"key": "guardduty", "name": "GuardDuty",
     "chain": "behaviour -> finding", "why": "Managed detection over CloudTrail, DNS and VPC flow logs. You already pay to generate all three."},
    {"key": "config", "name": "AWS Config",
     "chain": "state -> history", "why": "The only control that answers what this account looked like last Tuesday and who changed it."},
    {"key": "sec-hub", "name": "Security Hub",
     "chain": "findings -> one queue", "why": "Aggregation. The difference between having signals and having a SOC."},
    {"key": "athena", "name": "CloudTrail Queryable",
     "chain": "past -> answerable", "why": "The trail delivering to S3 is what lets you hunt history after the fact."},
]


def load_fixture(name):
    # The SAME fixtures detect.py --selftest judges. One fixture set, one
    # scanner, two renderings. A private copy here would be a second thing to
    # keep in sync, and it would eventually drift.
    with open(APP_DIR.parent / "detect" / "fixtures" / name) as fh:
        return json.load(fh)


def preflight():
    """Can we reach AWS at all, quickly?

    Without this the page hangs. boto3's default credential chain ends by
    asking the EC2 instance metadata service, and on a laptop that address
    goes nowhere and times out over several retries. A student with no
    credentials configured would stare at a spinner for the better part of a
    minute and conclude the lab is broken.

    So: one cheap STS call with a hard 2-second budget and retries off. If it
    fails we fall back immediately and say why. Fail fast and say so beats
    hang silently, which is the same lesson the alert path teaches.
    """
    import boto3
    from botocore.config import Config

    cfg = Config(connect_timeout=2, read_timeout=3,
                 retries={"max_attempts": 1, "mode": "standard"})
    ident = boto3.client("sts", region_name=REGION, config=cfg) \
                 .get_caller_identity()
    return ident.get("Account", "unknown")


def gather():
    """Return (snapshot, source, note). Live if we can reach the account."""
    forced = request.args.get("source") if request else None
    if forced == "blind":
        return load_fixture("blind.json"), "fixture", "Forced: bundled BLIND fixture."
    if forced == "wired":
        return load_fixture("wired.json"), "fixture", "Forced: bundled WIRED fixture."

    try:
        account = preflight()
    except Exception as exc:
        return (load_fixture("blind.json"), "fixture",
                f"No usable AWS credentials ({type(exc).__name__}). Showing the "
                f"bundled BLIND fixture — this is a simulation, not your account. "
                f"Run `aws sts get-caller-identity` to check your session.")

    try:
        snap = detect.collect_live(PROJECT, REGION)
        return (snap, "live",
                f"Live read of account {account}, region {REGION}, "
                f"project prefix {PROJECT}. Deploy or destroy and refresh — "
                f"this screen follows your account.")
    except Exception as exc:
        return (load_fixture("blind.json"), "fixture",
                f"Credentials work (account {account}) but the read failed "
                f"({type(exc).__name__}: {exc}). Showing the bundled BLIND "
                f"fixture — this is a simulation, not your account.")


def judge(snap):
    """Run the CLI scanner's own checks and group the findings by surface."""
    findings = detect.run_checks(snap)
    by_surface = {s["key"]: [] for s in SURFACES}
    for sev, svc, res, msg in findings:
        by_surface.setdefault(svc, []).append(
            {"sev": sev, "resource": res, "msg": msg})

    cards = []
    for s in SURFACES:
        gaps = by_surface.get(s["key"], [])
        cards.append({**s, "gaps": gaps, "ok": len(gaps) == 0,
                      "worst": ("HIGH" if any(g["sev"] == "HIGH" for g in gaps)
                                else "MEDIUM" if gaps else "")})
    highs = sum(1 for f in findings if f[0] == "HIGH")
    return {
        "cards": cards,
        "total": len(findings),
        "highs": highs,
        "verdict": "WIRED" if not findings else "BLIND",
    }


@app.route("/")
def home():
    return Response(PAGE, mimetype="text/html")


@app.route("/scan")
def scan():
    try:
        snap, source, note = gather()
        result = judge(snap)
        result.update({"source": source, "note": note,
                       "project": PROJECT, "region": REGION})
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": f"{type(exc).__name__}: {exc}",
                        "trace": traceback.format_exc()[-800:]}), 500


@app.route("/health")
def health():
    return Response("ok", mimetype="text/plain")


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Console | Chapter 10 | HackWithZach</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@600;700&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
  :root{--red:#e11d2a;--green:#1db954;--amber:#e8a33d;--bg:#0a0b0d;--panel:#141518;--line:#26282d;--dim:#8b8f98;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:#fff;font-family:Inter,system-ui,sans-serif}
  header{border-bottom:1px solid var(--line);padding:18px 26px;display:flex;align-items:center;gap:18px;flex-wrap:wrap}
  h1{font-family:'Chakra Petch',sans-serif;font-size:20px;margin:0;letter-spacing:.5px}
  .brand{color:var(--red);font-weight:700}
  .eyebrow{color:var(--dim);font-size:12px;letter-spacing:1.5px;text-transform:uppercase}
  main{padding:22px 26px;max-width:1240px}
  .bar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
  button{font-family:Inter;font-weight:600;font-size:13px;padding:10px 18px;border-radius:6px;border:1px solid var(--line);background:#1b1d21;color:#fff;cursor:pointer}
  button.primary{background:var(--red);border-color:var(--red)}
  button:hover{filter:brightness(1.15)}
  .verdict{font-family:'Chakra Petch',sans-serif;font-size:34px;letter-spacing:2px;padding:14px 22px;border-radius:8px;border:2px solid;display:inline-block}
  .blind{color:var(--red);border-color:var(--red);background:rgba(225,29,42,.08)}
  .wired{color:var(--green);border-color:var(--green);background:rgba(29,185,84,.08)}
  .note{color:var(--dim);font-size:13px;margin:10px 0 18px;line-height:1.6}
  .src{display:inline-block;font-size:11px;font-weight:700;letter-spacing:1px;padding:4px 10px;border-radius:4px;text-transform:uppercase}
  .live{background:rgba(29,185,84,.15);color:var(--green);border:1px solid var(--green)}
  .fixture{background:rgba(232,163,61,.15);color:var(--amber);border:1px solid var(--amber)}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:14px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;border-left:4px solid var(--line)}
  .card.bad{border-left-color:var(--red)}
  .card.good{border-left-color:var(--green)}
  .card h3{font-family:'Chakra Petch',sans-serif;margin:0 0 3px;font-size:15px}
  .chain{color:var(--dim);font-size:11px;letter-spacing:.5px;margin-bottom:9px;font-family:ui-monospace,monospace}
  .why{color:#c8ccd4;font-size:12px;line-height:1.55;margin-bottom:10px}
  .state{font-weight:700;font-size:12px;letter-spacing:1px}
  .state.bad{color:var(--red)} .state.good{color:var(--green)}
  .gap{font-size:11.5px;color:#d8dbe0;border-top:1px solid var(--line);padding-top:8px;margin-top:8px;line-height:1.5}
  .sev{font-weight:700;font-size:10px;padding:1px 6px;border-radius:3px;margin-right:6px}
  .HIGH{background:var(--red)} .MEDIUM{background:var(--amber);color:#000}
  footer{color:var(--dim);font-size:11.5px;padding:24px 26px;border-top:1px solid var(--line);margin-top:26px;line-height:1.7}
  code{background:#1b1d21;padding:1px 6px;border-radius:3px;font-size:11px}
</style>
</head>
<body>
<header>
  <div>
    <div class="eyebrow">Chapter 10 &middot; Pillar: Cloud</div>
    <h1>SOC Console &mdash; blind vs wired <span class="brand">| HackWithZach</span></h1>
  </div>
</header>
<main>
  <div class="bar">
    <button class="primary" onclick="scan()">Scan my account</button>
    <button onclick="scan('blind')">Show BLIND (fixture)</button>
    <button onclick="scan('wired')">Show WIRED (fixture)</button>
    <span id="src"></span>
  </div>
  <div id="verdict"></div>
  <div class="note" id="note">Press <b>Scan my account</b>. This calls the same
    <code>detect.run_checks()</code> your CLI run calls &mdash; there is one scanner,
    and this page is a second rendering of it, never a second opinion.</div>
  <div class="grid" id="grid"></div>
</main>
<footer>
  Eight surfaces, one chain: <b>event &rarr; CloudTrail &rarr; Logs &rarr; filter &rarr; alarm &rarr; confirmed subscriber &rarr; a human</b>.
  A break anywhere means it happened and nobody was paged.<br>
  Terminal equivalent: <code>python detect\detect.py --project hwz --region us-east-1</code>
</footer>
<script>
async function scan(force){
  const url = force ? '/scan?source=' + force : '/scan';
  document.getElementById('note').textContent = 'Reading…';
  const r = await fetch(url); const d = await r.json();
  if(d.error){ document.getElementById('note').textContent = d.error; return; }
  document.getElementById('src').innerHTML =
    '<span class="src ' + d.source + '">' + d.source + '</span>';
  document.getElementById('verdict').innerHTML =
    '<div class="verdict ' + (d.verdict==='WIRED'?'wired':'blind') + '">' + d.verdict +
    '</div><div class="note">' + (d.verdict==='WIRED'
      ? 'Every surface alarms. If it happens, you will see it.'
      : d.total + ' gap(s), ' + d.highs + ' HIGH. The SOC is blind — it happens and no one is paged.') + '</div>';
  document.getElementById('note').textContent = d.note;
  document.getElementById('grid').innerHTML = d.cards.map(c => `
    <div class="card ${c.ok?'good':'bad'}">
      <h3>${c.name}</h3>
      <div class="chain">${c.chain}</div>
      <div class="why">${c.why}</div>
      <div class="state ${c.ok?'good':'bad'}">${c.ok?'PRESENT':'MISSING'}</div>
      ${c.gaps.map(g => `<div class="gap"><span class="sev ${g.sev}">${g.sev}</span>${g.msg}</div>`).join('')}
    </div>`).join('');
}
scan();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    print(f"HWZ Chapter 10 SOC Console -> http://localhost:{PORT}")
    print(f"  project={PROJECT}  region={REGION}")
    print("  Reads live AWS through detect/detect.py. Falls back to fixtures "
          "and says so on screen.")
    app.run(host="127.0.0.1", port=PORT, debug=False)
