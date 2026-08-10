#!/usr/bin/env python3
"""
Chapter 14 — Vibe Coding Security, as a visual lab.

    pip install flask
    python app.py            # http://localhost:5114

WHY THIS ONE LOOKS DIFFERENT FROM THE OTHER VISUAL LABS
--------------------------------------------------------
Every other console in this course renders the posture of a deployed account.
This pillar has no account. The thing being judged is an artifact that has not
been applied yet, so the console shows the two generations side by side -- the
AI's unedited output and the same request with the control map in the prompt --
and runs the real gate against both.

Like every other console here, it contains no checks of its own. It imports
`../scan/scan.py`, which in turn imports the Chapter 8 scanner. Three layers,
one definition of "secure".

(c) 2026 Vigilantia Technologies INC. TM HackWithZach.
"""
import json
import os
import sys
from pathlib import Path

from flask import Flask, Response, jsonify, request

APP_DIR = Path(__file__).resolve().parent
MODULE_DIR = APP_DIR.parent
sys.path.insert(0, str(MODULE_DIR / "scan"))

import scan as gate  # noqa: E402

FIXTURES = MODULE_DIR / "scan" / "fixtures"
GENERATED = MODULE_DIR / "generated"

BUILDS = {
    "weak": {
        "snapshot": FIXTURES / "ai-generated-insecure.json",
        "tf": GENERATED / "weak" / "main.tf",
        "prompt": GENERATED / "prompts" / "01-weak-prompt.txt",
    },
    "hardened": {
        "snapshot": FIXTURES / "ai-generated-hardened.json",
        "tf": GENERATED / "hardened" / "main.tf",
        "prompt": GENERATED / "prompts" / "02-hardened-prompt.txt",
    },
}

app = Flask(__name__)


def judge(which):
    spec = BUILDS[which]
    ch8 = gate.load_ch8()
    with open(spec["snapshot"], encoding="utf-8") as fh:
        snap = json.load(fh)
    findings = gate.run_artifact_checks(ch8, snap)
    _, deferred = gate.artifact_checks(ch8)
    return {
        "build": which,
        "findings": [{"sev": s, "svc": v, "res": r, "msg": m}
                     for s, v, r, m in findings],
        "highs": sum(1 for f in findings if f[0] == "HIGH"),
        "verdict": "PASS" if not findings else "BUILD FAILS",
        "exit_code": 0 if not findings else 1,
        "deferred": sorted(d.__name__ for d in deferred),
        "tf": spec["tf"].read_text(encoding="utf-8") if spec["tf"].exists() else "",
        "prompt": spec["prompt"].read_text(encoding="utf-8") if spec["prompt"].exists() else "",
    }


@app.route("/api/judge/<which>")
def api_judge(which):
    if which not in BUILDS:
        return jsonify({"error": "unknown build"}), 404
    return jsonify(judge(which))


@app.route("/health")
def health():
    return Response("ok", mimetype="text/plain")


PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pre-Deploy Gate | HackWithZach</title>
<style>
 :root{--red:#C8102E;--grn:#12b76a;--bg:#070705;--card:#111110;--line:#26261f;--dim:#9a9a90}
 *{box-sizing:border-box} body{margin:0;background:var(--bg);color:#f2f2ee;
   font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif}
 header{border-bottom:3px solid var(--red);padding:16px 26px;display:flex;
   align-items:center;gap:14px}
 header b{font-size:19px} .sp{flex:1} .tag{color:var(--dim);font-size:12.5px}
 .wrap{padding:22px 26px;max-width:1280px;margin:0 auto}
 .seg{display:inline-flex;border:1px solid var(--line);border-radius:9px;overflow:hidden}
 .seg button{background:#16160f;color:#ddd;border:0;padding:11px 20px;font-weight:700;
   cursor:pointer;font-size:14px}
 .seg button.on-red{background:var(--red);color:#fff}
 .seg button.on-grn{background:var(--grn);color:#04150c}
 .verdict{margin:18px 0;padding:15px 18px;border-radius:11px;font-weight:800;font-size:17px}
 .v-fail{background:rgba(200,16,46,.13);border:1px solid var(--red);color:#ff6a7d}
 .v-pass{background:rgba(18,183,106,.13);border:1px solid var(--grn);color:#4ade9b}
 .grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
 @media(max-width:980px){.grid{grid-template-columns:1fr}}
 .card{background:var(--card);border:1px solid var(--line);border-radius:13px;padding:16px 18px}
 h2{font-size:12px;letter-spacing:.11em;text-transform:uppercase;color:var(--dim);
   margin:0 0 12px}
 pre{background:#0b0b08;border:1px solid var(--line);border-radius:9px;padding:12px;
   overflow:auto;max-height:390px;font-size:12.3px;line-height:1.5;color:#d8d8cf}
 .f{border-left:3px solid var(--red);background:#140b0d;padding:9px 12px;margin:8px 0;
   border-radius:0 8px 8px 0;font-size:13.4px}
 .f.med{border-left-color:#f5a524;background:#141008}
 .f.low{border-left-color:#6b7280;background:#0f1012}
 .sev{font-weight:800;font-size:11.5px;letter-spacing:.06em}
 .note{color:var(--dim);font-size:12.6px;margin-top:12px}
 code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
 footer{color:var(--dim);font-size:12px;text-align:center;padding:26px}
</style></head><body>
<header><b>Pre-Deploy <span style="color:var(--red)">Gate</span></b>
 <span class="sp"></span><span class="tag">Chapter 14 &middot; Pillar 4 &mdash; Vibe Coding</span></header>
<div class="wrap">
  <div class="seg" id="seg">
    <button data-b="weak" class="on-red">AI output, unedited</button>
    <button data-b="hardened">Same ask + control map</button>
  </div>
  <div id="verdict" class="verdict v-fail">Loading…</div>
  <div class="grid">
    <div class="card"><h2>The gate</h2><div id="findings"></div>
      <div class="note" id="deferred"></div></div>
    <div class="card"><h2>What was generated</h2><pre id="tf"></pre></div>
  </div>
  <div class="card" style="margin-top:18px"><h2>The prompt that produced it</h2>
    <pre id="prompt"></pre></div>
  <div class="note">Terminal equivalent:
    <code>python scan/scan.py --snapshot scan/fixtures/ai-generated-insecure.json</code>
    &nbsp;&middot;&nbsp; exit code is what fails the build.</div>
</div>
<footer>&copy; 2026 Vigilantia Technologies INC. &trade; HackWithZach. Education / defense only.</footer>
<script>
 let build="weak";
 function esc(s){return (s||"").replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
 async function load(){
   const r=await fetch("/api/judge/"+build); const j=await r.json();
   const v=document.getElementById("verdict");
   const pass=j.exit_code===0;
   v.className="verdict "+(pass?"v-pass":"v-fail");
   v.textContent=pass
     ? "\\u2714  PASS \\u2014 no findings. Safe to apply. (exit 0)"
     : "\\u2716  BUILD FAILS \\u2014 "+j.findings.length+" finding(s), "+j.highs+" HIGH. Never reaches an account. (exit 1)";
   document.getElementById("findings").innerHTML = j.findings.length
     ? j.findings.map(f=>'<div class="f '+(f.sev==="MEDIUM"?"med":f.sev==="LOW"?"low":"")+'">'
         +'<span class="sev">'+f.sev+'</span> &nbsp;'+esc(f.svc)+' &middot; <b>'+esc(f.res)+'</b><br>'
         +esc(f.msg)+'</div>').join("")
     : '<div class="f" style="border-left-color:var(--grn);background:#08140e">'
       +'<span class="sev">CLEAN</span><br>Every check the artifact can answer, answered.</div>';
   document.getElementById("deferred").textContent =
     "Deferred to the account scan, not answerable before deploy: "+j.deferred.join(", ")+".";
   document.getElementById("tf").textContent=j.tf;
   document.getElementById("prompt").textContent=j.prompt;
 }
 document.querySelectorAll("#seg button").forEach(b=>b.addEventListener("click",()=>{
   build=b.dataset.b;
   document.querySelectorAll("#seg button").forEach(x=>x.className="");
   b.className = build==="weak" ? "on-red" : "on-grn";
   load();
 }));
 load();
</script></body></html>"""


@app.route("/")
def home():
    return Response(PAGE, mimetype="text/html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5114"))   # 5100 + chapter
    print(f"\n  Pre-Deploy Gate — Chapter 14\n  open:  http://localhost:{port}\n")
    app.run(host="127.0.0.1", port=port, debug=False)
