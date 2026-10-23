#!/usr/bin/env python3
###############################################################################
# visual/app.py  -- the Chapter 14 teaching console and live bench, port 5115.
#
# Two things live here:
#   /         the console: reads the two real source files and runs the real
#             scanner against them, live, on every load. Nothing is hand-typed.
#   /attack   the bench: the live store in a frame, with a button for each
#             finding, and a toggle between the weak store and the hardened one.
#
# WHY THE BENCH NOW PROXIES THE STORES
# The old bench put the store in an iframe pointed straight at a different port
# (127.0.0.1:5200). A cross-origin frame to another port is fragile: if the
# store process was not up, or the browser declined the frame, you got a blank
# panel and no error, which is why the attack "never worked" for some people.
#
# This version reverse-proxies the stores through this same origin:
#   /live/weak/...  -> 127.0.0.1:5200      (the vibe-coded store)
#   /live/hard/...  -> 127.0.0.1:5201      (the hardened store)
# The frame is now same-origin, so it always renders and the address bar in the
# frame is readable. Root-absolute links in the store's HTML are rewritten to
# the proxy prefix, so every link and form inside the frame keeps working. If a
# store process is down, the frame shows a plain message with the command to
# start it, instead of a silent blank. Everything stays on localhost.
#
# Run:  python3 visual/app.py      then open http://127.0.0.1:5115
#
# NOTE: this file is the teaching bench, not a store, and it is not part of the
# gated surface. Scanning it reports a few findings (the word "password" in the
# demo HTML, the reset button's POST): that is the scanner applied to a file it
# was not built to gate. The gate runs on weak/app.py and hardened/app.py. A
# student who scans this file and asks why is having exactly the Chapter 14
# conversation about what a gate covers and what it does not.
###############################################################################
import html
import os
import re
import sys
import urllib.error
import urllib.request

from flask import Flask, request, Response, redirect

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "appscan"))
import appscan  # noqa: E402  the same gate, imported, not shelled out to

app = Flask(__name__)

WEAK = os.path.join(ROOT, "weak", "app.py")
HARD = os.path.join(ROOT, "hardened", "app.py")
ADMIN = os.path.join(ROOT, "hardened", "admin.py")
P_WEAK = os.path.join(ROOT, "prompts", "01-weak-prompt.txt")
P_HARD = os.path.join(ROOT, "prompts", "02-hardened-prompt.txt")

CHAPTER = {
    "secret-in-source": "Ch 8 — secrets",
    "secret-to-client": "Ch 8 — secrets",
    "identity-in-request": "Ch 9 — API auth",
    "sql-interpolation": "Ch 9 — API security",
    "shell-from-request": "Ch 9 — input handling",
    "model-output-as-command": "Ch 12 & 13 — the bound tool",
    "unescaped-output": "Ch 9 — output encoding",
    "plaintext-passwords": "Ch 8 — foundation",
    "missing-authorization": "Ch 9 — broken access control",
    "debug-mode-on": "Ch 8 — configuration",
    "no-waf": "Ch 9 — input firewall",
    "no-input-validation": "Ch 9 — validate at the edge",
    "admin-not-isolated": "Ch 10 — plane isolation",
    "llm-overprivileged": "Ch 12 & 13 — least privilege",
    "prompt-concatenation": "Ch 11 — the channel boundary",
    "no-rate-limit": "Ch 9 — abuse",
    "missing-csrf": "Ch 9 — request forgery",
    "binds-all-interfaces": "Ch 10 — exposure",
    "no-audit-log": "Ch 3 — detection",
    "no-model-audit-log": "Ch 13 — detection",
    "no-security-headers": "Ch 9 — defense in depth",
}

SEV_CLASS = {"HIGH": "high", "MEDIUM": "med", "LOW": "low"}


def read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError as e:
        return "could not read %s: %s" % (path, e)


def gate(path):
    found = appscan.scan(path)
    highs = sum(1 for c, _ in found if c["sev"] == appscan.HIGH)
    verdict = "NAKED — %d gaps, %d HIGH" % (len(found), highs) if found \
        else "PASS — no findings"
    return verdict, highs, len(found), found


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Catch the Assistant</title>
<style>
:root{--bg:#0d0f14;--panel:#141821;--line:#232a37;--ink:#e8ebf2;--muted:#8893a8;
  --weak:#ff5c6c;--hard:#38d39f;--accent:#6ea8ff;--high:#ff5c6c;--med:#ffb020;
  --low:#7d8aa5;--code:#0a0c11}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial}
header{padding:26px 32px 18px;border-bottom:1px solid var(--line);
  background:linear-gradient(180deg,#141a26,#0d0f14)}
h1{margin:0;font-size:25px;letter-spacing:-.4px}
h1 .ch{color:var(--accent);font-weight:600}
.sub{color:var(--muted);margin-top:5px;font-size:14px}
main{max-width:1180px;margin:0 auto;padding:26px 24px 80px}
section{margin:30px 0}
.step{display:flex;align-items:baseline;gap:11px;margin-bottom:12px}
.step .n{font-variant-numeric:tabular-nums;color:var(--accent);font-weight:700;
  font-size:13px;border:1px solid var(--accent);border-radius:999px;width:26px;
  height:26px;display:grid;place-items:center;flex:0 0 auto}
.step h2{margin:0;font-size:18px}
.step .note{color:var(--muted);font-size:13px}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:760px){.cols{grid-template-columns:1fr}}
.pane{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.pane .tab{padding:9px 14px;font-size:12.5px;font-weight:700;letter-spacing:.3px;
  text-transform:uppercase;border-bottom:1px solid var(--line);display:flex;
  justify-content:space-between;align-items:center}
.pane.w .tab{color:var(--weak)} .pane.h .tab{color:var(--hard)}
.verdict{font-size:12px;font-weight:700;padding:3px 9px;border-radius:999px}
.verdict.bad{background:rgba(255,92,108,.14);color:var(--weak)}
.verdict.good{background:rgba(56,211,159,.14);color:var(--hard)}
pre{margin:0;padding:14px 16px;background:var(--code);color:#cdd6e6;
  font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  overflow:auto;max-height:440px;white-space:pre}
pre.short{max-height:none}
.prompt{padding:16px;white-space:pre-wrap;font:13px/1.6 ui-monospace,monospace;
  background:var(--code);color:#cdd6e6;max-height:360px;overflow:auto}
.findings{width:100%;border-collapse:collapse;font-size:13.5px;background:var(--panel);
  border:1px solid var(--line);border-radius:12px;overflow:hidden}
.findings th,.findings td{padding:10px 13px;border-bottom:1px solid var(--line);
  vertical-align:top;text-align:left}
.findings th{color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:.4px}
.findings tr:last-child td{border-bottom:0}
.sev{font-weight:700;font-size:11px;padding:2px 8px;border-radius:999px;white-space:nowrap}
.sev.high{background:rgba(255,92,108,.14);color:var(--high)}
.sev.med{background:rgba(255,176,32,.14);color:var(--med)}
.sev.low{background:rgba(125,138,165,.16);color:var(--low)}
.gid{font-family:ui-monospace,monospace;font-size:12.5px;color:var(--ink)}
.ch{color:var(--accent);font-size:12px;white-space:nowrap}
.closes{color:var(--hard)}
.kick{background:var(--panel);border:1px solid var(--line);border-left:3px solid
  var(--accent);border-radius:10px;padding:14px 18px;color:var(--muted);
  margin-top:14px;font-size:14px}
.kick b{color:var(--ink)}
.legend{color:var(--muted);font-size:12.5px;margin-top:8px}
footer{color:var(--muted);font-size:12px;text-align:center;padding:30px}
</style></head><body>
<header>
  <h1>Catch the Assistant <span class="ch">· Chapter 14 · the vibe-coding lab</span></h1>
  <div class="sub">One request, two answers. The only thing that changed between
  them is what the prompt demanded up front. The scanner below ran live against
  both files when this page loaded.</div>
  <div class="sub" style="margin-top:12px"><a href="/attack"
    style="color:var(--weak);font-weight:700;text-decoration:none;border:1px solid
    var(--weak);padding:7px 13px;border-radius:8px;display:inline-block">
    Open the live store and break it &rarr;</a></div>
</header>
<main>
<section>
  <div class="step"><span class="n">1</span><h2>The ask</h2>
    <span class="note">same model, same question, one carries requirements</span></div>
  <div class="cols">
    <div class="pane w"><div class="tab">The vibe prompt</div>
      <div class="prompt">{p_weak}</div></div>
    <div class="pane h"><div class="tab">With the control map</div>
      <div class="prompt">{p_hard}</div></div>
  </div>
</section>
<section>
  <div class="step"><span class="n">2</span><h2>The code it wrote</h2>
    <span class="note">unedited on the left, the control map applied on the right</span></div>
  <div class="cols">
    <div class="pane w"><div class="tab">weak/app.py</div><pre>{weak}</pre></div>
    <div class="pane h"><div class="tab">hardened/app.py</div><pre>{hard}</pre></div>
  </div>
</section>
<section>
  <div class="step"><span class="n">3</span><h2>The gate, run on both</h2>
    <span class="note">appscan reads source, not a Terraform plan</span></div>
  <div class="cols">
    <div class="pane w"><div class="tab">appscan weak/app.py
      <span class="verdict bad">{weak_verdict}</span></div>
      <pre class="short">{weak_scan}</pre></div>
    <div class="pane h"><div class="tab">appscan hardened/app.py
      <span class="verdict good">{hard_verdict}</span></div>
      <pre class="short">{hard_scan}</pre></div>
  </div>
  <div class="kick">The exit code is the whole mechanism. The left build exits
  non-zero on a HIGH finding, so in CI it <b>never reaches a server</b>. The
  right build exits zero and deploys. The admin console is a separate service
  (<code>hardened/admin.py</code>) and it passes the gate too.</div>
</section>
<section>
  <div class="step"><span class="n">4</span><h2>The gaps in full</h2>
    <span class="note">every one maps to a chapter you already finished</span></div>
  <table class="findings">
    <tr><th>Gap</th><th>Sev</th><th>What it means</th><th>What closes it</th>
      <th>Calls back to</th></tr>
    {rows}
  </table>
  <div class="legend">Severity and wording come straight from the scanner's
  CHECKS table. The chapter column is the point of the whole pillar: nothing
  here is a new kind of bug.</div>
</section>
</main>
<footer>HackWithZach · Chapter 14 · reads the live source and the live scanner,
nothing on this page is hand-typed · port 5115</footer>
</body></html>"""


@app.route("/")
def index():
    wv, wh, wt, wfound = gate(WEAK)
    hv, hh, ht, hfound = gate(HARD)
    import contextlib
    import io as _io

    def captured(path, found):
        buf = _io.StringIO()
        with contextlib.redirect_stdout(buf):
            appscan.report(path, found)
        return buf.getvalue().rstrip()

    rows = []
    for c, ev in wfound:
        rows.append(
            '<tr><td class="gid">%s</td><td><span class="sev %s">%s</span></td>'
            '<td>%s</td><td class="closes">%s</td><td class="ch">%s</td></tr>' % (
                html.escape(c["id"]), SEV_CLASS[c["sev"]], c["sev"],
                html.escape(c["means"]), html.escape(c["closes"]),
                html.escape(CHAPTER.get(c["id"], ""))))

    return PAGE.format(
        p_weak=html.escape(read(P_WEAK).strip()),
        p_hard=html.escape(read(P_HARD).strip()),
        weak=html.escape(read(WEAK)),
        hard=html.escape(read(HARD)),
        weak_scan=html.escape(captured(WEAK, wfound)),
        hard_scan=html.escape(captured(HARD, hfound)),
        weak_verdict=wv, hard_verdict=hv,
        rows="".join(rows))


# --------------------------------------------------------------------------
# The reverse proxy. Same-origin access to the live stores, so the frame always
# renders. Root-absolute links in the store HTML are rewritten to the proxy
# prefix. Everything is localhost to localhost.
# --------------------------------------------------------------------------
UPSTREAM = {"weak": "http://127.0.0.1:5200", "hard": "http://127.0.0.1:5201"}
START_CMD = {"weak": "python weak/app.py",
             "hard": "WIDGET_LAB_DEV=1 WIDGET_LLM_API_KEY=sk-demo python hardened/app.py"}
_ABS = re.compile(rb'(href|action|src)="/(?!/)')


def _rewrite_html(body, prefix):
    return _ABS.sub((r'\1="' + prefix + '/').encode(), body)


def _rewrite_location(loc, base, prefix):
    if loc.startswith(base):
        loc = loc[len(base):]
    if loc.startswith("/"):
        return prefix + loc
    return loc


@app.route("/live/<store>/", defaults={"path": ""},
           methods=["GET", "POST"])
@app.route("/live/<store>/<path:path>", methods=["GET", "POST"])
def live(store, path):
    if store not in UPSTREAM:
        return Response("unknown store", status=404)
    base = UPSTREAM[store]
    prefix = "/live/" + store
    url = base + "/" + path
    if request.query_string:
        url += "?" + request.query_string.decode()

    data = request.get_data() if request.method == "POST" else None
    headers = {}
    if request.headers.get("Content-Type"):
        headers["Content-Type"] = request.headers["Content-Type"]
    if request.headers.get("Cookie"):
        headers["Cookie"] = request.headers["Cookie"]
    req = urllib.request.Request(url, data=data, method=request.method,
                                 headers=headers)
    try:
        up = urllib.request.urlopen(req, timeout=8)
        status, raw, info = up.getcode(), up.read(), up.info()
    except urllib.error.HTTPError as e:
        status, raw, info = e.code, e.read(), e.headers
    except urllib.error.URLError:
        msg = ("<!doctype html><meta charset='utf-8'>"
               "<body style='font-family:system-ui;background:#0d0f14;color:#e8ebf2;padding:30px'>"
               "<h2>The %s store is not running.</h2>"
               "<p style='color:#8893a8'>Start it in a terminal, then reload this panel:</p>"
               "<pre style='background:#0a0c11;padding:12px;border-radius:8px;color:#cdd6e6'>%s</pre>"
               "</body>") % (html.escape(store), html.escape(START_CMD[store]))
        return Response(msg, status=200, content_type="text/html")

    ctype = info.get("Content-Type", "text/html")
    resp = Response(status=status)
    if "text/html" in ctype:
        resp.set_data(_rewrite_html(raw, prefix))
    else:
        resp.set_data(raw)
    resp.headers["Content-Type"] = ctype
    loc = info.get("Location")
    if loc:
        resp.headers["Location"] = _rewrite_location(loc, base, prefix)
    for sc in (info.get_all("Set-Cookie") or []):
        resp.headers.add("Set-Cookie", sc)
    return resp


# --------------------------------------------------------------------------
# The bench.
# --------------------------------------------------------------------------
ATTACK = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Break the store</title>
<style>
:root{--bg:#0d0f14;--panel:#141821;--line:#232a37;--ink:#e8ebf2;--muted:#8893a8;
  --weak:#ff5c6c;--hard:#38d39f;--accent:#6ea8ff;--code:#0a0c11}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial}
header{padding:18px 28px;border-bottom:1px solid var(--line);
  background:linear-gradient(180deg,#141a26,#0d0f14);display:flex;
  justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}
h1{margin:0;font-size:21px}
.toggle{display:flex;gap:0;border:1px solid var(--line);border-radius:8px;overflow:hidden}
.toggle button{background:#141821;color:var(--muted);border:0;padding:8px 16px;
  cursor:pointer;font:inherit;font-size:13px;font-weight:700}
.toggle button.on.weak{background:var(--weak);color:#120406}
.toggle button.on.hard{background:var(--hard);color:#04140d}
a.back{color:var(--accent);text-decoration:none;font-size:13px}
.wrap{display:grid;grid-template-columns:370px 1fr;gap:0;min-height:calc(100vh - 64px)}
@media(max-width:860px){.wrap{grid-template-columns:1fr}}
.rail{border-right:1px solid var(--line);padding:18px;overflow:auto}
.stage{padding:14px;display:flex;flex-direction:column;gap:10px}
.bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;font-size:12.5px;color:var(--muted)}
.bar .url{font-family:ui-monospace,monospace;color:#cdd6e6;background:var(--code);
  padding:5px 9px;border-radius:6px;border:1px solid var(--line);flex:1;overflow:auto;white-space:nowrap}
iframe{width:100%;height:72vh;border:1px solid var(--line);border-radius:10px;background:#0b0d11}
.card{border:1px solid var(--line);border-radius:11px;padding:13px 14px;margin-bottom:13px;background:var(--panel)}
.card h3{margin:0 0 3px;font-size:14.5px}
.card .fid{font-family:ui-monospace,monospace;font-size:11.5px;color:var(--weak)}
.card p{margin:7px 0 10px;font-size:12.8px;color:var(--muted)}
.btn{background:var(--weak);color:#120406;border:0;border-radius:7px;padding:8px 12px;
  font-weight:700;font-size:12.5px;cursor:pointer;width:100%;font-family:inherit}
.btn.calm{background:#232a37;color:var(--ink)}
.closes{color:var(--hard);font-size:12px;margin-top:9px;display:block}
textarea{width:100%;background:var(--code);border:1px solid var(--line);color:#fff;
  border-radius:6px;padding:8px;font-family:ui-monospace,monospace;font-size:12px;resize:vertical}
.intro{color:var(--muted);font-size:12.5px;margin-bottom:14px;line-height:1.5}
.warn{color:var(--weak)}.reset{margin-top:6px}
form{margin:0}
.hbadge{font-size:11px;color:var(--hard)}
</style></head><body>
<header>
  <h1>Break the store</h1>
  <div class="toggle">
    <button id="tw" class="on weak" onclick="setStore('weak')">weak &middot; 5200</button>
    <button id="th" class="hard" onclick="setStore('hard')">hardened &middot; 5201</button>
  </div>
  <a class="back" href="/">&larr; back to the code and the gate</a>
</header>
<div class="wrap">
  <div class="rail">
    <div class="intro">The live store runs in the frame on the right, proxied
    through this page so it always renders. Each button drives it the way a
    customer's browser would. Flip the toggle to run the <b>same</b> moves
    against the hardened store and watch every one refused.
    <span class="warn" id="downhint" style="display:none"></span></div>

    <div class="card">
      <div class="fid">identity-in-request + admin-not-isolated</div>
      <h3>Walk into the admin console</h3>
      <p>In the weak store the role rides in the URL, and admin lives in the same
      app. Change one word and the admin page opens, passwords and all.</p>
      <button class="btn" onclick="go('/admin?user=1&name=alice&role=admin')">
        Change role=user to role=admin</button>
      <span class="closes">Hardened: there is no admin route in the storefront.
      It is a separate service on 5202. This returns 404.</span>
    </div>

    <div class="card">
      <div class="fid">missing-authorization (IDOR)</div>
      <h3>Read another customer's order</h3>
      <p>Order 1003 belongs to someone else. Ask for it by number and the weak
      store hands it over.</p>
      <button class="btn" onclick="go('/orders?user=1&name=alice&role=user&id=1003')">
        Open order 1003 as Alice</button>
      <span class="closes">Hardened: the query matches id AND owner, and you need
      a session. This refuses you.</span>
    </div>

    <div class="card">
      <div class="fid">model-output-as-command + llm-overprivileged</div>
      <h3>Set the price with a sentence</h3>
      <p>The weak store reads the chatbot's reply for a marker and writes it onto
      every price. Send this, then reopen the catalog.</p>
      <form id="askform" method="post" target="store">
        <textarea name="question" rows="2">can I get a discount?</textarea>
        <button class="btn" style="margin-top:8px">Send it to the assistant</button>
      </form>
      <button class="btn calm" style="margin-top:8px"
        onclick="go('/catalog?user=1&name=alice&role=user')">
        Reopen the catalog and read the prices</button>
      <span class="closes">Hardened: the assistant has a read-only role and no
      price capability. It answers that it cannot change prices, and every price
      holds.</span>
    </div>

    <div class="card">
      <div class="fid">sql-interpolation + no-waf</div>
      <h3>Inject SQL in the search box</h3>
      <p>The weak search box builds SQL by string formatting. Drop a quote in and
      watch the query break.</p>
      <button class="btn" onclick="go('/catalog?user=1&role=user&q=%27%20OR%20%271%27=%271')">
        Search for ' OR '1'='1</button>
      <span class="closes">Hardened: the term is a bound parameter, and the WAF
      refuses the pattern at the door with a 403.</span>
    </div>

    <div class="card">
      <div class="fid">the payoff</div>
      <h3>Buy the whole catalog for nothing</h3>
      <p>Zero the prices above, then fill the cart and check out. The weak store
      accepts the order at $0.00, no payment step.</p>
      <button class="btn" onclick="fillCart()">Add all four widgets to the cart</button>
      <button class="btn calm" style="margin-top:8px"
        onclick="go('/cart?user=1&name=alice&role=user')">Open the cart</button>
      <span class="closes">Hardened: the total is recomputed from list_price at
      checkout, a column only the admin service writes.</span>
    </div>

    <div class="card">
      <div class="fid">secret-in-source + secret-to-client</div>
      <h3>Find the API key in the page</h3>
      <p>The weak store renders the key into the page script. Open the home page,
      then View Source and search for LLM_KEY.</p>
      <button class="btn" onclick="go('/catalog?user=1&name=alice&role=user')">Open the store</button>
      <span class="closes">Hardened: the key is read server side and never
      rendered. There is nothing in the page.</span>
    </div>

    <div class="card reset">
      <h3>Put the store back</h3>
      <p>Reseeds both databases so prices and data are fresh for the next run.</p>
      <button class="btn calm" onclick="resetStore()">Reset the store</button>
    </div>
  </div>

  <div class="stage">
    <div class="bar"><span id="who">frame (weak):</span>
      <span class="url" id="url"></span></div>
    <iframe name="store" id="store"></iframe>
  </div>
</div>
<script>
var STORE = "weak";
var LANDING = "/catalog?user=1&name=alice&role=user";
function prefix(){ return "/live/" + STORE; }
function go(path){
  var f = document.getElementById('store');
  f.src = prefix() + path;
  document.getElementById('url').textContent = prefix() + path;
}
function setStore(s){
  STORE = s;
  document.getElementById('tw').className = (s==='weak'?'on ':'') + 'weak';
  document.getElementById('th').className = (s==='hard'?'on ':'') + 'hard';
  document.getElementById('who').textContent = 'frame (' + s + '):';
  document.getElementById('askform').action = prefix() + '/ask?user=1&role=user';
  go(LANDING);
}
document.getElementById('store').addEventListener('load', function(){
  try { document.getElementById('url').textContent =
        this.contentWindow.location.pathname + this.contentWindow.location.search; } catch(e){}
});
function fillCart(){
  var p = prefix();
  var calls = [1,2,3,4].map(function(i){
    return fetch(p + '/cart/add?user=1&name=alice&role=user&id=' + i, {credentials:'same-origin'});
  });
  Promise.all(calls).then(function(){ go('/cart?user=1&name=alice&role=user'); })
                    .catch(function(){ go('/cart?user=1&name=alice&role=user'); });
}
function resetStore(){
  fetch('/attack/reset', {method:'POST'}).then(function(){ go(LANDING); });
}
setStore('weak');
</script>
</body></html>"""


@app.route("/attack")
def attack():
    return ATTACK


@app.route("/attack/reset", methods=["POST"])
def attack_reset():
    import importlib.util
    seed_path = os.path.join(ROOT, "seed.py")
    spec = importlib.util.spec_from_file_location("seed", seed_path)
    seed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seed)
    seed.build(os.path.join(ROOT, "weak", "store.db"), hashed=False)
    seed.build(os.path.join(ROOT, "hardened", "store.db"), hashed=True)
    return ("reseeded", 200)


if __name__ == "__main__":
    for p in (WEAK, HARD, P_WEAK, P_HARD):
        if not os.path.exists(p):
            raise SystemExit("missing %s -- run from the widget-store folder" % p)
    print("Chapter 14 console on http://127.0.0.1:5115")
    print("  the code and the gate     : http://127.0.0.1:5115/")
    print("  the live store, to break  : http://127.0.0.1:5115/attack")
    print("  (start the stores too: python weak/app.py ; "
          "WIDGET_LAB_DEV=1 WIDGET_LLM_API_KEY=sk-demo python hardened/app.py)")
    app.run(host="127.0.0.1", port=5115, debug=False)
