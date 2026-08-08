#!/usr/bin/env python3
"""
hwzvisual.py — the shared renderer behind every HackWithZach visual lab.

ONE RULE, AND IT IS THE WHOLE POINT
-----------------------------------
A visual lab never reimplements a check and never talks to AWS itself. It
imports its own module's scanner and renders what that scanner returns:

    snap = scanner.collect_live(project, region)
    gaps = scanner.run_checks(snap)

One scanner, two renderings. It is structurally impossible for the browser and
the terminal to disagree, because there is only one thing to disagree with. If
they could diverge, students would eventually stop trusting both, and a
security tool nobody trusts is worse than no tool at all.

THREE STATES, NOT TWO
---------------------
Cards are PRESENT (green), MISSING (red), or UNTESTED (amber). UNTESTED exists
because of a real bug: a check that loops over an upstream list returns zero
findings when that list is empty, and rendering that as green tells a student a
control is verified when it was never evaluated. No findings is not the same
fact as no problems. That distinction is how audits get faked, so the UI has to
carry it.

This file is copied into each module's visual/ directory rather than imported
across modules, so a student can clone one chapter folder and have everything
that chapter needs.

(c) 2026 Vigilantia Technologies INC. TM HackWithZach. Education/defense only.
"""
import json
import os
import traceback

from flask import Flask, Response, jsonify, request


# ---------------------------------------------------------------------------
# FINDING NORMALISATION
# The scanners grew up at different times and return two shapes. Rather than
# rewrite five working scanners to match a UI, the UI adapts. Never make a
# proven tool change shape to suit a screen.
# ---------------------------------------------------------------------------
def normalise(finding):
    """Accept (sev, group, resource, msg) tuples or {check,severity,message}
    dicts and return one dict shape."""
    if isinstance(finding, dict):
        return {"sev": finding.get("severity", "MEDIUM"),
                "group": finding.get("check", ""),
                "resource": finding.get("resource", ""),
                "msg": finding.get("message", "")}
    sev, group, resource, msg = finding
    return {"sev": sev, "group": group, "resource": resource, "msg": msg}


class VisualLab:
    """Config-driven visual lab. Each module supplies its scanner and cards."""

    def __init__(self, *, scanner, chapter, title, subtitle, pillar,
                 cards, weak_word, hard_word, weak_line, hard_line,
                 cli_hint, demo_snapshots, project=None, region=None,
                 chain_footer="", needs_aws=True):
        self.scanner = scanner
        self.chapter = chapter
        self.title = title
        self.subtitle = subtitle
        self.pillar = pillar
        self.cards = cards            # [{key,name,chain,why,requires?,requires_label?}]
        self.weak_word = weak_word    # e.g. "BLIND"
        self.hard_word = hard_word    # e.g. "WIRED"
        self.weak_line = weak_line
        self.hard_line = hard_line
        self.cli_hint = cli_hint
        self.demo = demo_snapshots    # {"weak": dict-or-callable, "hardened": ...}
        self.chain_footer = chain_footer
        # Some modules' collect_live() reads a posture file Terraform wrote,
        # not the AWS API. Doing an STS preflight for those would show a
        # credentials warning for a lab that needs no credentials.
        self.needs_aws = needs_aws
        self.project = project or os.environ.get("HWZ_PROJECT", "hwz")
        self.region = region or os.environ.get("AWS_REGION", "us-east-1")
        self.port = int(os.environ.get("PORT", str(5100 + chapter)))

    # -- data ------------------------------------------------------------
    def _demo(self, which):
        d = self.demo[which]
        return d() if callable(d) else d

    def preflight(self):
        """Fail fast if AWS is unreachable.

        Without this the page hangs: boto3's credential chain ends at the EC2
        instance metadata service, and on a laptop that address goes nowhere
        and burns through retries. A student with no credentials would stare at
        a spinner and conclude the lab is broken. One cheap call, hard 2-second
        budget, retries off. Fail fast and say why.
        """
        import boto3
        from botocore.config import Config
        cfg = Config(connect_timeout=2, read_timeout=3,
                     retries={"max_attempts": 1, "mode": "standard"})
        return boto3.client("sts", region_name=self.region,
                            config=cfg).get_caller_identity().get("Account", "?")

    def gather(self, forced=None):
        if forced in ("weak", "hardened"):
            return (self._demo(forced), "fixture",
                    f"Forced: bundled {forced.upper()} sample. Not your account.")
        account = None
        if self.needs_aws:
            try:
                account = self.preflight()
            except Exception as exc:
                return (self._demo("weak"), "fixture",
                        f"No usable AWS credentials ({type(exc).__name__}). Showing "
                        f"the bundled WEAK sample — a simulation, not your account. "
                        f"Check with `aws sts get-caller-identity`.")
        try:
            snap = self.scanner.collect_live(self.project, self.region)
            where = f"account {account}, " if account else ""
            return (snap, "live",
                    f"Live read of {where}region {self.region}, project prefix "
                    f"{self.project}. Deploy or destroy and refresh — this screen "
                    f"follows your stack.")
        except Exception as exc:
            return (self._demo("weak"), "fixture",
                    f"Read failed ({type(exc).__name__}: {exc}). Showing the "
                    f"bundled WEAK sample — a simulation, not your account.")

    def judge(self, snap):
        raw = [normalise(f) for f in self.scanner.run_checks(snap)]
        by_group = {}
        for f in raw:
            by_group.setdefault(f["group"], []).append(f)

        out, unplaced = [], dict(by_group)
        for c in self.cards:
            gaps = unplaced.pop(c["key"], [])
            req = c.get("requires")
            if gaps:
                state = "MISSING"
            elif req and not snap.get(req):
                state = "UNTESTED"
            else:
                state = "PRESENT"
            out.append({**c, "gaps": gaps, "state": state,
                        "note": c.get("requires_label", "") if state == "UNTESTED" else ""})

        # A finding whose group matches no card would vanish silently. Surface
        # it instead: a dashboard that quietly drops a finding is the same
        # failure as one that renders unevaluated as green.
        for key, gaps in unplaced.items():
            out.append({"key": key, "name": key, "chain": "", "state": "MISSING",
                        "why": "Reported by the scanner with no card defined for it.",
                        "gaps": gaps, "note": ""})

        return {"cards": out, "total": len(raw),
                "highs": sum(1 for f in raw if f["sev"] == "HIGH"),
                "untested": sum(1 for c in out if c["state"] == "UNTESTED"),
                "verdict": self.hard_word if not raw else self.weak_word}

    # -- app -------------------------------------------------------------
    def flask_app(self):
        app = Flask(__name__)

        @app.route("/")
        def home():
            return Response(self.page(), mimetype="text/html")

        @app.route("/scan")
        def scan():
            try:
                snap, source, note = self.gather(request.args.get("source"))
                r = self.judge(snap)
                r.update({"source": source, "note": note, "project": self.project,
                          "region": self.region, "weak": self.weak_word,
                          "hard": self.hard_word,
                          "weak_line": self.weak_line, "hard_line": self.hard_line})
                return jsonify(r)
            except Exception as exc:
                return jsonify({"error": f"{type(exc).__name__}: {exc}",
                                "trace": traceback.format_exc()[-800:]}), 500

        @app.route("/health")
        def health():
            return Response("ok", mimetype="text/plain")

        return app

    def run(self):
        print(f"HWZ Chapter {self.chapter} — {self.title}")
        print(f"  -> http://localhost:{self.port}")
        print(f"  project={self.project}  region={self.region}")
        print("  Renders this module's own scanner. Falls back to samples and "
              "says so on screen.")
        self.flask_app().run(host="127.0.0.1", port=self.port, debug=False)

    # -- page ------------------------------------------------------------
    def page(self):
        return PAGE_TMPL.replace("__TITLE__", self.title) \
                        .replace("__SUB__", self.subtitle) \
                        .replace("__PILLAR__", self.pillar) \
                        .replace("__CH__", str(self.chapter)) \
                        .replace("__WEAK__", self.weak_word) \
                        .replace("__HARD__", self.hard_word) \
                        .replace("__CLI__", self.cli_hint) \
                        .replace("__CHAIN__", self.chain_footer)


PAGE_TMPL = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__ | Chapter __CH__ | HackWithZach</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@600;700&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
  :root{--red:#e11d2a;--green:#1db954;--amber:#e8a33d;--bg:#0a0b0d;--panel:#141518;--line:#26282d;--dim:#8b8f98;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:#fff;font-family:Inter,system-ui,sans-serif}
  header{border-bottom:1px solid var(--line);padding:18px 26px}
  h1{font-family:'Chakra Petch',sans-serif;font-size:20px;margin:0;letter-spacing:.5px}
  .brand{color:var(--red);font-weight:700}
  .eyebrow{color:var(--dim);font-size:12px;letter-spacing:1.5px;text-transform:uppercase}
  main{padding:22px 26px;max-width:1240px}
  .bar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
  button{font-family:Inter;font-weight:600;font-size:13px;padding:10px 18px;border-radius:6px;border:1px solid var(--line);background:#1b1d21;color:#fff;cursor:pointer}
  button.primary{background:var(--red);border-color:var(--red)}
  button:hover{filter:brightness(1.15)}
  .verdict{font-family:'Chakra Petch',sans-serif;font-size:34px;letter-spacing:2px;padding:14px 22px;border-radius:8px;border:2px solid;display:inline-block}
  .bad{color:var(--red);border-color:var(--red);background:rgba(225,29,42,.08)}
  .good{color:var(--green);border-color:var(--green);background:rgba(29,185,84,.08)}
  .note{color:var(--dim);font-size:13px;margin:10px 0 18px;line-height:1.6}
  .src{display:inline-block;font-size:11px;font-weight:700;letter-spacing:1px;padding:4px 10px;border-radius:4px;text-transform:uppercase}
  .live{background:rgba(29,185,84,.15);color:var(--green);border:1px solid var(--green)}
  .fixture{background:rgba(232,163,61,.15);color:var(--amber);border:1px solid var(--amber)}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:14px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;border-left:4px solid var(--line)}
  .card.MISSING{border-left-color:var(--red)}
  .card.PRESENT{border-left-color:var(--green)}
  .card.UNTESTED{border-left-color:var(--amber)}
  .card h3{font-family:'Chakra Petch',sans-serif;margin:0 0 3px;font-size:15px}
  .chain{color:var(--dim);font-size:11px;letter-spacing:.5px;margin-bottom:9px;font-family:ui-monospace,monospace}
  .why{color:#c8ccd4;font-size:12px;line-height:1.55;margin-bottom:10px}
  .state{font-weight:700;font-size:12px;letter-spacing:1px}
  .state.MISSING{color:var(--red)} .state.PRESENT{color:var(--green)} .state.UNTESTED{color:var(--amber)}
  .gap{font-size:11.5px;color:#d8dbe0;border-top:1px solid var(--line);padding-top:8px;margin-top:8px;line-height:1.5}
  .untested{font-size:11.5px;color:var(--amber);border-top:1px solid var(--line);padding-top:8px;margin-top:8px;line-height:1.5}
  .sev{font-weight:700;font-size:10px;padding:1px 6px;border-radius:3px;margin-right:6px}
  .HIGH{background:var(--red)} .MEDIUM{background:var(--amber);color:#000} .LOW{background:#3a3d44}
  footer{color:var(--dim);font-size:11.5px;padding:24px 26px;border-top:1px solid var(--line);margin-top:26px;line-height:1.7}
  code{background:#1b1d21;padding:1px 6px;border-radius:3px;font-size:11px}
</style>
</head>
<body>
<header>
  <div class="eyebrow">Chapter __CH__ &middot; __PILLAR__</div>
  <h1>__TITLE__ <span class="brand">| HackWithZach</span></h1>
  <div class="note" style="margin:6px 0 0">__SUB__</div>
</header>
<main>
  <div class="bar">
    <button class="primary" onclick="scan()">Scan my stack</button>
    <button onclick="scan('weak')">Show __WEAK__ (sample)</button>
    <button onclick="scan('hardened')">Show __HARD__ (sample)</button>
    <span id="src"></span>
  </div>
  <div id="verdict"></div>
  <div class="note" id="note">Press <b>Scan my stack</b>. This calls the same
    <code>run_checks()</code> your CLI run calls &mdash; one scanner, and this page is a
    second rendering of it, never a second opinion.</div>
  <div class="grid" id="grid"></div>
</main>
<footer>
  __CHAIN__<br>
  <b>Amber = UNTESTED</b>: that check could not run because nothing upstream exists.
  No findings is not the same fact as no problems.<br>
  Terminal equivalent: <code>__CLI__</code>
</footer>
<script>
async function scan(force){
  document.getElementById('note').textContent = 'Reading…';
  const r = await fetch(force ? '/scan?source=' + force : '/scan');
  const d = await r.json();
  if(d.error){ document.getElementById('note').textContent = d.error; return; }
  const ok = d.verdict === d.hard;
  document.getElementById('src').innerHTML = '<span class="src ' + d.source + '">' + d.source + '</span>';
  document.getElementById('verdict').innerHTML =
    '<div class="verdict ' + (ok?'good':'bad') + '">' + d.verdict + '</div>' +
    '<div class="note">' + (ok ? d.hard_line
      : d.total + ' gap(s), ' + d.highs + ' HIGH' +
        (d.untested ? ', and ' + d.untested + ' check(s) could not be evaluated at all' : '') +
        '. ' + d.weak_line) + '</div>';
  document.getElementById('note').textContent = d.note;
  document.getElementById('grid').innerHTML = d.cards.map(c => `
    <div class="card ${c.state}">
      <h3>${c.name}</h3>
      ${c.chain ? `<div class="chain">${c.chain}</div>` : ''}
      <div class="why">${c.why}</div>
      <div class="state ${c.state}">${c.state}</div>
      ${c.gaps.map(g => `<div class="gap"><span class="sev ${g.sev}">${g.sev}</span>${g.msg}</div>`).join('')}
      ${c.note ? `<div class="untested">Not evaluated — ${c.note}. No findings here is not the same fact as no problems.</div>` : ''}
    </div>`).join('');
}
scan();
</script>
</body>
</html>
"""
