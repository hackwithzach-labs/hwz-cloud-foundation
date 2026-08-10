#!/usr/bin/env python3
"""
Chapter 15 — the Capstone, as a visual lab.

    pip install -r requirements.txt
    python app.py            # http://localhost:5115

One poisoned ticket, five gates, two profiles. Flip the profile and watch the
same payload go from BREACH to BLOCKED.

Like every console in this course it contains no logic of its own: it imports
`../attack/end_to_end.py` and `../scan/scan.py` and renders what they return.
If the browser and the terminal ever disagree, one of them is lying, and this
design makes that impossible.

(c) 2026 Vigilantia Technologies INC. TM HackWithZach.
"""
import os
import sys
from pathlib import Path

from flask import Flask, Response, jsonify

APP_DIR = Path(__file__).resolve().parent
MODULE_DIR = APP_DIR.parent
sys.path.insert(0, str(MODULE_DIR / "attack"))
sys.path.insert(0, str(MODULE_DIR / "scan"))

import end_to_end as chain   # noqa: E402
import scan as capscan       # noqa: E402

app = Flask(__name__)

TICKETS = {
    "poisoned": MODULE_DIR / "attack" / "tickets" / "poisoned.txt",
    "clean": MODULE_DIR / "attack" / "tickets" / "clean.txt",
}


@app.route("/api/run/<profile>/<ticket>")
def api_run(profile, ticket):
    if profile not in ("weak", "hardened") or ticket not in TICKETS:
        return jsonify({"error": "unknown profile or ticket"}), 404
    locks = {g: (profile == "hardened") for g, _, _ in chain.GATES}
    text = chain.load_ticket(str(TICKETS[ticket]))
    breached, steps, trace, soc = chain.run_chain(text, locks)
    posture = capscan.posture_weak() if profile == "weak" else capscan.posture_hardened()
    findings = capscan.run_checks(posture)
    return jsonify({
        "profile": profile,
        "ticket": ticket,
        "ticket_text": text,
        "breached": breached,
        "steps": [{"n": n, "gate": g, "state": s, "msg": m} for n, g, s, m in steps],
        "trace": trace,
        "soc": soc,
        "findings": [{"sev": s, "pillar": p, "ch": c, "name": n, "why": w}
                     for s, p, c, n, w in findings],
    })


@app.route("/api/independence")
def api_independence():
    """The book claims each preventive lock holds alone. Show the evidence."""
    text = chain.load_ticket(str(TICKETS["poisoned"]))
    out = []
    for lock in ("guardrail", "goal-lock", "tool-least-priv", "hitl-approval", "run-audit"):
        locks = {g: (g == lock) for g, _, _ in chain.GATES}
        breached, steps, _, _ = chain.run_chain(text, locks)
        out.append({"lock": lock, "holds": not breached,
                    "stopped_at": steps[-1]["gate"] if isinstance(steps[-1], dict)
                    else steps[-1][1],
                    "preventive": lock != "run-audit"})
    return jsonify({"results": out})


@app.route("/health")
def health():
    return Response("ok", mimetype="text/plain")


PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Capstone — One Payload, Every Layer | HackWithZach</title>
<style>
 :root{--red:#C8102E;--grn:#12b76a;--amb:#f5a524;--bg:#070705;--card:#111110;
   --line:#26261f;--dim:#9a9a90}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:#f2f2ee;
   font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif}
 header{border-bottom:3px solid var(--red);padding:16px 26px;display:flex;
   align-items:center;gap:14px}
 header b{font-size:19px}.sp{flex:1}.tag{color:var(--dim);font-size:12.5px}
 .wrap{padding:22px 26px;max-width:1320px;margin:0 auto}
 .bar{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
 .seg{display:inline-flex;border:1px solid var(--line);border-radius:9px;overflow:hidden}
 .seg button{background:#16160f;color:#ddd;border:0;padding:11px 20px;font-weight:700;
   cursor:pointer;font-size:14px}
 .seg button.on-red{background:var(--red);color:#fff}
 .seg button.on-grn{background:var(--grn);color:#04150c}
 .seg button.on-neu{background:#2b2b22;color:#fff}
 .lbl{color:var(--dim);font-size:12px;letter-spacing:.09em;text-transform:uppercase}
 .verdict{margin:18px 0;padding:15px 18px;border-radius:11px;font-weight:800;font-size:17px}
 .v-breach{background:rgba(200,16,46,.13);border:1px solid var(--red);color:#ff6a7d}
 .v-blocked{background:rgba(18,183,106,.13);border:1px solid var(--grn);color:#4ade9b}
 .grid{display:grid;grid-template-columns:1.25fr 1fr;gap:18px}
 @media(max-width:1040px){.grid{grid-template-columns:1fr}}
 .card{background:var(--card);border:1px solid var(--line);border-radius:13px;padding:16px 18px}
 h2{font-size:12px;letter-spacing:.11em;text-transform:uppercase;color:var(--dim);margin:0 0 12px}
 .gate{display:flex;gap:12px;align-items:flex-start;padding:11px 12px;margin:8px 0;
   border-radius:9px;border-left:3px solid var(--line);background:#0d0d0a}
 .gate.off{border-left-color:var(--red);background:#140b0d}
 .gate.on{border-left-color:var(--grn);background:#08140e}
 .gn{font-weight:800;color:var(--dim);min-width:18px}
 .gname{font-weight:700}
 .gstate{font-size:11px;font-weight:800;letter-spacing:.07em;padding:2px 7px;border-radius:5px;
   margin-left:8px}
 .gstate.OFF{background:var(--red);color:#fff}.gstate.ON{background:var(--grn);color:#04150c}
 .gmsg{color:#cfcfc6;font-size:13.6px;margin-top:3px}
 pre{background:#0b0b08;border:1px solid var(--line);border-radius:9px;padding:11px;
   overflow:auto;font-size:12.2px;line-height:1.5;color:#d8d8cf;max-height:220px;margin:0}
 .empty{color:var(--dim);font-size:13px;line-height:1.6}
 .f{border-left:3px solid var(--red);background:#140b0d;padding:8px 11px;margin:7px 0;
   border-radius:0 8px 8px 0;font-size:13.2px}
 .f.med{border-left-color:var(--amb);background:#141008}
 .sev{font-weight:800;font-size:11px;letter-spacing:.06em}
 table{width:100%;border-collapse:collapse;font-size:13.4px}
 td{padding:7px 6px;border-bottom:1px solid var(--line)}
 .hold{color:#4ade9b;font-weight:800}.fail{color:#ff6a7d;font-weight:800}
 .note{color:var(--dim);font-size:12.6px;margin-top:12px}
 code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
 footer{color:var(--dim);font-size:12px;text-align:center;padding:26px}
</style></head><body>
<header><b>Capstone — <span style="color:var(--red)">One Payload, Every Layer</span></b>
 <span class="sp"></span><span class="tag">Chapter 15 &middot; all four pillars</span></header>
<div class="wrap">
  <div class="bar">
    <span class="lbl">Profile</span>
    <div class="seg" id="profSeg">
      <button data-p="weak" class="on-red">baseline.tfvars</button>
      <button data-p="hardened">hardened.tfvars</button>
    </div>
    <span class="lbl">Ticket</span>
    <div class="seg" id="tickSeg">
      <button data-t="poisoned" class="on-neu">Poisoned</button>
      <button data-t="clean">Clean</button>
    </div>
  </div>

  <div id="verdict" class="verdict v-breach">Loading…</div>

  <div class="grid">
    <div class="card"><h2>The chain, gate by gate</h2><div id="gates"></div></div>
    <div>
      <div class="card"><h2>Agent trace — what happened</h2><div id="trace"></div></div>
      <div class="card" style="margin-top:18px"><h2>SOC — what reached a human</h2>
        <div id="soc"></div></div>
    </div>
  </div>

  <div class="grid" style="margin-top:18px">
    <div class="card"><h2>Capstone scan — every pillar</h2><div id="findings"></div></div>
    <div class="card"><h2>Does each lock hold alone?</h2>
      <table id="indep"></table>
      <div class="note">Defense in depth means independent locks, not one lock
        and three spectators. <b>run-audit is detection, not prevention</b> — it
        is why you find out, not why it did not happen.</div></div>
  </div>

  <div class="note">Terminal equivalent:
    <code>python3 attack/end_to_end.py --ticket attack/tickets/poisoned.pdf</code> ·
    <code>python3 scan/scan.py --green-wall</code></div>
</div>
<footer>&copy; 2026 Vigilantia Technologies INC. &trade; HackWithZach. Education / defense only.</footer>
<script>
 let prof="weak", tick="poisoned";
 function esc(s){return (s||"").replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
 function j2(o){return esc(JSON.stringify(o));}
 async function load(){
   const r=await fetch(`/api/run/${prof}/${tick}`); const d=await r.json();
   const v=document.getElementById("verdict");
   v.className="verdict "+(d.breached?"v-breach":"v-blocked");
   v.textContent=d.breached
     ? "\\u2716  BREACH \\u2014 the chain completed. The customer table left the building."
     : (tick==="clean"
        ? "\\u2714  OK \\u2014 normal ticket, handled. The locks do not break the product."
        : "\\u2714  BLOCKED \\u2014 same payload, stopped at the first lock.");
   document.getElementById("gates").innerHTML = d.steps.map(s=>
     '<div class="gate '+(s.state==="ON"?"on":"off")+'">'
     +'<div class="gn">'+s.n+'</div><div><div><span class="gname">'+esc(s.gate)+'</span>'
     +'<span class="gstate '+s.state+'">'+s.state+'</span></div>'
     +'<div class="gmsg">'+esc(s.msg)+'</div></div></div>').join("");
   document.getElementById("trace").innerHTML = d.trace.length
     ? '<pre>'+d.trace.map(j2).join("\\n")+'</pre>'
     : '<div class="empty">Nothing — the chain died before the agent acted.</div>';
   document.getElementById("soc").innerHTML = d.soc.length
     ? '<pre>'+d.soc.map(j2).join("\\n")+'</pre>'
     : '<div class="empty">Nothing reached a human. The events on the left still '
       +'happened — the log group filled up and no metric filter was watching it. '
       +'<b>"It was logged" and "we found out" are two different claims.</b></div>';
   document.getElementById("findings").innerHTML = d.findings.length
     ? d.findings.map(f=>'<div class="f '+(f.sev==="MEDIUM"?"med":"")+'">'
        +'<span class="sev">'+f.sev+'</span> &nbsp;'+esc(f.pillar)+' &middot; '+esc(f.ch)
        +' &middot; <b>'+esc(f.name)+'</b><br>'+esc(f.why)+'</div>').join("")
     : '<div class="f" style="border-left-color:var(--grn);background:#08140e">'
       +'<span class="sev">PASS</span><br>Every pillar wired.</div>';
 }
 async function indep(){
   const d=await (await fetch("/api/independence")).json();
   document.getElementById("indep").innerHTML = d.results.map(r=>
     '<tr><td><b>'+esc(r.lock)+'</b></td>'
     +'<td>'+(r.preventive?"preventive":"detection")+'</td>'
     +'<td class="'+(r.holds?"hold":"fail")+'">'
     +(r.holds?"HOLDS alone":"does not stop it")+'</td></tr>').join("");
 }
 function wire(id,attr,set){
   document.querySelectorAll("#"+id+" button").forEach(b=>b.addEventListener("click",()=>{
     set(b.dataset[attr]);
     document.querySelectorAll("#"+id+" button").forEach(x=>x.className="");
     b.className = id==="profSeg" ? (prof==="weak"?"on-red":"on-grn") : "on-neu";
     load();
   }));
 }
 wire("profSeg","p",v=>prof=v); wire("tickSeg","t",v=>tick=v);
 load(); indep();
</script></body></html>"""


@app.route("/")
def home():
    return Response(PAGE, mimetype="text/html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5115"))   # 5100 + chapter
    print(f"\n  Capstone — One Payload, Every Layer (Chapter 15)")
    print(f"  open:  http://localhost:{port}\n")
    app.run(host="127.0.0.1", port=port, debug=False)
