#!/usr/bin/env python3
###############################################################################
# hardened/app.py  -- the storefront, with the control map applied.
#
# Same request as weak/app.py. The only thing that changed is that the ask
# carried the control map you have built since Chapter 8, written out as
# requirements. appscan reports no findings on this file:
#
#   python3 appscan/appscan.py hardened/app.py      # PASS
#
# What is different, control by control:
#   - identity-in-request  -> a signed session holds the user id; the role is
#                             read from the database, never from the request.
#   - sql-interpolation    -> every query is parameterised.
#   - shell-from-request   -> there is no shell in this file at all.
#   - secret-in-source     -> keys come from the environment; none is rendered.
#   - model-output / IAM   -> the assistant has a named read-only role and a
#                             capability allow-list (guardrails.py). Its reply
#                             is display text. Pricing is server side, from
#                             list_price, a column only the admin service writes.
#   - input guardrails     -> every request value is validated (guardrails.py).
#   - output guardrails    -> one escape helper at every render; no |safe.
#   - WAF                  -> every request is screened for OWASP input classes
#                             and prompt injection before a view runs (waf.py).
#   - logging              -> every security event is one audit line (audit.py).
#   - admin isolation      -> there is NO admin route here. Admin is a separate
#                             service on its own port, admin.py, port 5202.
#   - rate limit, CSRF, security headers, debug off, localhost bind -> below.
#
# Run:  WIDGET_LAB_DEV=1 WIDGET_LLM_API_KEY=sk-demo python3 hardened/app.py
###############################################################################
import os
import sys
import time
import secrets
import sqlite3
import functools

from flask import (Flask, request, redirect, url_for, session, g, abort,
                   render_template_string)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)      # audit.py, waf.py, guardrails.py are siblings
sys.path.insert(0, ROOT)      # seed.py (the password KDF) is one level up

import audit          # noqa: E402
import waf            # noqa: E402
import guardrails     # noqa: E402
import seed           # noqa: E402  the salted KDF and its constant-time verify

app = Flask(__name__)

# --------------------------------------------------------------------------
# CLOSES secret-in-source: the signing key and the model key come from the
# environment. The app refuses to start without a signing key, because a
# missing secret is a finding, not a convenience. WIDGET_LAB_DEV=1 permits an
# ephemeral key for a localhost class; production has neither shortcut.
# --------------------------------------------------------------------------
_signing_key = os.environ.get("WIDGET_SIGNING_KEY")
if not _signing_key:
    if os.environ.get("WIDGET_LAB_DEV") == "1":
        _signing_key = secrets.token_urlsafe(32)
        print("WIDGET_LAB_DEV: using an ephemeral signing key. Sessions will "
              "not survive a restart. Never do this in production.",
              file=sys.stderr)
    else:
        raise SystemExit("Refusing to start: set WIDGET_SIGNING_KEY, or "
                         "WIDGET_LAB_DEV=1 for a localhost class.")

# The model key is read server side and never rendered to a client.
LLM_API_KEY = os.environ.get("WIDGET_LLM_API_KEY", "")

app.config.update(
    SECRET_KEY=_signing_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Secure cookies off only in the localhost dev class, on everywhere else.
    SESSION_COOKIE_SECURE=os.environ.get("WIDGET_LAB_DEV") != "1",
    PERMANENT_SESSION_LIFETIME=1800,
)

DB = os.path.join(HERE, "store.db")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


# --------------------------------------------------------------------------
# CLOSES no-waf: screen every request for OWASP input classes and prompt
# injection before any view runs. Defense in depth, not the only control.
# --------------------------------------------------------------------------
app.before_request(waf.block)


# CLOSES no-security-headers: a Content-Security-Policy with no inline script,
# nosniff, frame-options and a referrer policy on every response.
@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = \
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


# --------------------------------------------------------------------------
# CLOSES identity-in-request: the user id lives in a signed session cookie, and
# the role is read from the database on every request, never from the client.
# --------------------------------------------------------------------------
def current_user():
    uid = session.get("uid")
    if uid is None:
        return None
    row = db().execute(
        "SELECT id, username, role FROM users WHERE id = ?", (uid,)).fetchone()
    if row is None:
        session.clear()
        return None
    return {"id": row["id"], "name": row["username"], "role": row["role"]}


def require_user(fn):
    """Auth gate. An anonymous request to a protected view is refused, never
    silently treated as a guest."""
    @functools.wraps(fn)
    def wrap(*a, **k):
        if current_user() is None:
            audit.log("auth.denied", path=request.path, remote=request.remote_addr)
            return redirect(url_for("login_page"))
        return fn(*a, **k)
    return wrap


# CLOSES missing-csrf: a per-session token in every state-changing form,
# compared in constant time, with SameSite on the cookie behind it.
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    sent = request.form.get("csrf", "")
    held = session.get("csrf", "")
    if not held or not secrets.compare_digest(sent, held):
        audit.log("csrf.reject", path=request.path)
        abort(403, "CSRF token missing or invalid.")


# CLOSES no-rate-limit: the login route counts attempts per source and locks
# out on a threshold. One message for both failure cases.
_ATTEMPTS = {}
_LIMIT, _WINDOW = 5, 300


def rate_limit(key):
    now = time.time()
    hits = [t for t in _ATTEMPTS.get(key, []) if now - t < _WINDOW]
    hits.append(now)
    _ATTEMPTS[key] = hits
    return len(hits) > _LIMIT


# --------------------------------------------------------------------------
# Templates. Jinja autoescaping is on, and nothing uses |safe, so every value
# is escaped at the point of rendering (CLOSES unescaped-output). Values are
# passed as data, never as pre-built HTML strings.
# --------------------------------------------------------------------------
SHELL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Widget Store</title><style>
body{font-family:system-ui,Arial;background:#0f1115;color:#e9e9ee;margin:0;padding:28px}
a{color:#7fb6ff}.card{background:#171a21;border:1px solid #262b36;border-radius:10px;padding:16px;margin:14px 0}
input,textarea{background:#0b0d11;border:1px solid #2a3040;color:#fff;border-radius:6px;padding:8px;width:100%;box-sizing:border-box}
.btn{background:#1f8f5f;color:#fff;border:0;border-radius:6px;padding:9px 14px;cursor:pointer}
.price{color:#4ade80;font-weight:700}.muted{color:#8b93a7;font-size:13px}
table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid #262b36;padding:7px;text-align:left}
.ok{color:#38d39f}
</style></head><body>
<h1>Widget Store <span class="muted" style="font-size:13px">hardened</span></h1>
<p class="muted">
{% if user %}Signed in as <b>{{ user.name }}</b> ({{ user.role }}) &middot;
<a href="{{ url_for('catalog') }}">catalog</a> &middot;
<a href="{{ url_for('orders') }}">your orders</a> &middot;
<a href="{{ url_for('logout') }}">sign out</a>
{% else %}<a href="{{ url_for('catalog') }}">catalog</a> &middot;
<a href="{{ url_for('login_page') }}">sign in</a>{% endif %}
</p>
{% block body %}{% endblock %}
</body></html>"""


def render(inner, **ctx):
    tmpl = SHELL.replace("{% block body %}{% endblock %}", inner)
    return render_template_string(tmpl, user=current_user(), csrf=csrf_token(), **ctx)


@app.route("/")
def home():
    return redirect(url_for("catalog"))


@app.route("/login", methods=["GET"])
def login_page():
    inner = """<div class="card"><h2>Sign in</h2>
    <form method="post" action="{{ url_for('login') }}">
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <p><input name="username" placeholder="username"></p>
      <p><input name="password" type="password" placeholder="password"></p>
      <button class="btn">Sign in</button></form>
    <p class="muted">Try alice / alice123</p></div>"""
    return render(inner)


@app.route("/login", methods=["POST"])
def login():
    check_csrf()
    if rate_limit("login:" + (request.remote_addr or "?")):
        audit.log("login.ratelimited", remote=request.remote_addr)
        abort(429, "Too many attempts. Wait a few minutes and try again.")
    # CLOSES sql-interpolation: the username is a bound parameter.
    username = guardrails.clean_str(request.form.get("username"), "username", 64)
    password = guardrails.clean_str(request.form.get("password"), "password", 128)
    row = db().execute(
        "SELECT id, password FROM users WHERE username = ?", (username,)).fetchone()
    # CLOSES plaintext-passwords: constant-time verify against a salted KDF hash.
    if row is None or not seed.verify(password, row["password"]):
        audit.log("login.fail", username=username, remote=request.remote_addr)
        return render("""<div class="card">Wrong username or password.</div>""")
    session.clear()
    session["uid"] = row["id"]
    session.permanent = True
    audit.log("login.ok", uid=row["id"], remote=request.remote_addr)
    return redirect(url_for("catalog"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/catalog")
def catalog():
    # Public browsing. The search term is a bound LIKE parameter, and prices are
    # read from list_price, the column only the admin service can change.
    term = guardrails.clean_str(request.args.get("q", ""), "q", 64)
    rows = db().execute(
        "SELECT id, name, list_price, blurb FROM widgets WHERE name LIKE ? "
        "ORDER BY list_price", ("%" + term + "%",)).fetchall()
    recent = db().execute(
        "SELECT author, body FROM reviews ORDER BY id DESC LIMIT 5").fetchall()
    inner = """<div class="card"><h2>Catalog</h2>
      <form method="get" action="{{ url_for('catalog') }}">
        <p><input name="q" placeholder="search widgets" value="{{ q }}"></p></form>
      <table><tr><th>Widget</th><th>Price</th><th>About</th><th></th></tr>
      {% for w in widgets %}<tr><td>{{ w.name }}</td>
        <td class="price">${{ '%.2f'|format(w.list_price) }}</td>
        <td>{{ w.blurb }}</td>
        <td>{% if user %}<form method="post" action="{{ url_for('cart_add') }}" style="margin:0">
          <input type="hidden" name="csrf" value="{{ csrf }}">
          <input type="hidden" name="widget" value="{{ w.id }}">
          <button class="btn">add to cart</button></form>{% else %}
          <a href="{{ url_for('login_page') }}">sign in to buy</a>{% endif %}</td></tr>
      {% endfor %}</table>
      {% if user %}<p class="muted"><a href="{{ url_for('cart') }}">view cart</a></p>{% endif %}
      </div>
      <div class="card"><h2>Ask about widgets</h2>
      <form method="post" action="{{ url_for('ask') }}">
        <input type="hidden" name="csrf" value="{{ csrf }}">
        <p><textarea name="question" rows="3" placeholder="which widget is best for outdoor use?"></textarea></p>
        <button class="btn">Ask</button></form></div>
      <div class="card"><h2>Recent reviews</h2><ul>
      {% for r in reviews %}<li><b>{{ r.author }}</b>: {{ r.body }}</li>{% endfor %}</ul>
      {% if user %}<form method="post" action="{{ url_for('review') }}">
        <input type="hidden" name="csrf" value="{{ csrf }}">
        <input type="hidden" name="widget" value="1">
        <p><input name="text" placeholder="leave a review"></p>
        <button class="btn">Post</button></form>{% endif %}</div>"""
    return render(inner, q=term, widgets=rows, reviews=recent)


# --------------------------------------------------------------------------
# The assistant. CLOSES model-output-as-command, prompt-concatenation,
# llm-overprivileged, no-model-audit-log.
#
# The instruction and the user's text are separate arguments, never one string.
# The reply is display text, run through the output guardrail. The assistant
# holds guardrails.ASSISTANT_ROLE, a read-only capability allow-list, so there
# is no price write for a sentence to reach and no marker to parse. Every call
# is logged.
# --------------------------------------------------------------------------
SYSTEM_PROMPT = ("You are the Widget Store assistant. You help customers choose "
                 "widgets by describing the catalogue. You cannot change prices, "
                 "apply discounts, place orders or read accounts.")


def call_model(system, user):
    """Stub for the provider call, which would happen server side with
    LLM_API_KEY. The instruction and the user's text stay separate; the stub
    never grants a capability it does not hold."""
    # The assistant's capability check: describing the catalogue is allowed;
    # anything that would move money or state is simply not on the allow-list.
    if not guardrails.assistant_can("answer.text"):
        return "I am not able to help with that."
    wants_price_change = any(w in user.lower() for w in
                             ("discount", "free", "zero", "set the price", "lower the price"))
    if wants_price_change:
        return ("I cannot change prices. Pricing is set by the store, and the "
                "catalogue always shows the current price.")
    return ("The Alpha Widget suits most general use, and the Gamma Widget holds "
            "up best outdoors. Prices are on the catalogue.")


@app.route("/ask", methods=["POST"])
def ask():
    # No CSRF token here on purpose: the assistant is read-only and changes no
    # state, so there is nothing for a forged request to accomplish. CSRF tokens
    # guard the state-changing POSTs (login, cart, checkout, review).
    question = guardrails.clean_str(request.form.get("question", ""), "question", 500)
    model_text = call_model(SYSTEM_PROMPT, question)
    # CLOSES no-model-audit-log: who asked, what they asked, what came back.
    audit.log("assistant.answer", role=guardrails.ASSISTANT_ROLE,
              question=question[:120], remote=request.remote_addr)
    # CLOSES unescaped-output: the reply is display text, escaped at render.
    inner = """<div class="card"><h2>Assistant</h2>
      <p>{{ answer }}</p>
      <p class="muted ok">Prices are unchanged. This answer cannot move them.</p>
      <p><a href="{{ url_for('catalog') }}">back to catalog</a></p></div>"""
    return render(inner, answer=guardrails.safe_answer(model_text))


# --------------------------------------------------------------------------
# Cart and checkout. CLOSES identity-in-request (cart keyed to the signed
# session), missing-authorization (orders fetched by id AND owner), and the
# free-checkout payoff (the total is recomputed from list_price server side,
# a column the assistant cannot touch).
# --------------------------------------------------------------------------
@app.route("/cart/add", methods=["POST"])
@require_user
def cart_add():
    check_csrf()
    wid = guardrails.require_int(request.form.get("widget"), "widget", lo=1)
    if db().execute("SELECT 1 FROM widgets WHERE id = ?", (wid,)).fetchone():
        cart = session.get("cart", [])
        session["cart"] = cart + [wid]
        session.modified = True
        audit.log("cart.add", uid=session.get("uid"), widget=wid)
    return redirect(url_for("cart"))


def _cart_lines():
    lines, total = [], 0.0
    for wid in session.get("cart", []):
        r = db().execute(
            "SELECT name, list_price FROM widgets WHERE id = ?", (wid,)).fetchone()
        if r:
            total += r["list_price"]
            lines.append((r["name"], r["list_price"]))
    return lines, total


@app.route("/cart")
@require_user
def cart():
    lines, total = _cart_lines()
    inner = """<div class="card"><h2>Cart</h2>
      {% if lines %}<table>
      {% for name, price in lines %}<tr><td>{{ name }}</td>
        <td class="price">${{ '%.2f'|format(price) }}</td></tr>{% endfor %}
      <tr><td><b>Total</b></td><td class="price"><b>${{ '%.2f'|format(total) }}</b></td></tr></table>
      <form method="post" action="{{ url_for('checkout') }}">
        <input type="hidden" name="csrf" value="{{ csrf }}">
        <button class="btn">Place order</button></form>
      {% else %}<p>Empty. <a href="{{ url_for('catalog') }}">catalog</a></p>{% endif %}</div>"""
    return render(inner, lines=lines, total=total)


@app.route("/checkout", methods=["POST"])
@require_user
def checkout():
    check_csrf()
    user = current_user()
    lines, total = _cart_lines()        # recomputed from list_price, server side
    if not lines:
        return redirect(url_for("catalog"))
    oid = (db().execute("SELECT COALESCE(MAX(id), 2000) + 1 AS n FROM orders")
           .fetchone()["n"])
    names = ", ".join(n for n, _ in lines)
    db().execute("INSERT INTO orders (id, item, total, buyer) VALUES (?, ?, ?, ?)",
                 (oid, names, total, user["name"]))
    db().commit()
    session["cart"] = []
    audit.log("checkout", uid=user["id"], order=oid, total=total)
    inner = """<div class="card"><h2>Order placed</h2>
      <p>Order {{ oid }} &middot; {{ names }}</p>
      <p class="price" style="font-size:22px">Total charged: ${{ '%.2f'|format(total) }}</p>
      <p><a href="{{ url_for('catalog') }}">back to catalog</a></p></div>"""
    return render(inner, oid=oid, names=names, total=total)


@app.route("/review", methods=["POST"])
@require_user
def review():
    check_csrf()
    user = current_user()
    text = guardrails.clean_str(request.form.get("text", ""), "review", 500)
    wid = guardrails.require_int(request.form.get("widget", "1"), "widget", lo=1)
    # CLOSES unescaped-output at the sink: bound parameters in, escaped out.
    db().execute("INSERT INTO reviews (widget_id, author, body) VALUES (?, ?, ?)",
                 (wid, user["name"], text))
    db().commit()
    audit.log("review.post", uid=user["id"], widget=wid)
    return redirect(url_for("catalog"))


@app.route("/orders")
@require_user
def orders():
    user = current_user()
    oid = request.args.get("id")
    if oid is not None:
        oid = guardrails.require_int(oid, "order id", lo=1)
        # CLOSES missing-authorization: fetched by id AND owner, in the query.
        r = db().execute(
            "SELECT id, item, total, buyer FROM orders WHERE id = ? AND buyer = ?",
            (oid, user["name"])).fetchone()
        if r is None:
            audit.log("order.denied", uid=user["id"], order=oid)
            abort(404, "No such order.")
        inner = """<div class="card"><h2>Order {{ o.id }}</h2>
          <p>{{ o.item }} &middot; ${{ '%.2f'|format(o.total) }} &middot; {{ o.buyer }}</p></div>"""
        return render(inner, o=r)
    rows = db().execute(
        "SELECT id, item, total FROM orders WHERE buyer = ? ORDER BY id DESC",
        (user["name"],)).fetchall()
    inner = """<div class="card"><h2>Your orders</h2><table>
      {% for o in rows %}<tr><td><a href="{{ url_for('orders') }}?id={{ o.id }}">{{ o.id }}</a></td>
      <td>{{ o.item }}</td><td class="price">${{ '%.2f'|format(o.total) }}</td></tr>{% endfor %}</table></div>"""
    return render(inner, rows=rows)


# CLOSES admin-not-isolated: there is no admin here. The admin console is a
# separate service, admin.py, on its own port with its own login and audit log.
# A request for /admin on the storefront is simply not a route it serves.
@app.errorhandler(403)
def forbidden(e):
    return render("""<div class="card"><h2>Refused</h2><p>{{ msg }}</p></div>""",
                  msg=getattr(e, "description", "Forbidden")), 403


@app.errorhandler(404)
def not_found(e):
    return render("""<div class="card"><h2>Not found</h2>
      <p>No such page. The admin console is a separate, authenticated service and
      is not reachable from the storefront.</p></div>"""), 404


@app.errorhandler(429)
def too_many(e):
    return render("""<div class="card"><h2>Slow down</h2><p>{{ msg }}</p></div>""",
                  msg=getattr(e, "description", "Too many requests")), 429


@app.teardown_appcontext
def close(_e):
    d = g.pop("db", None)
    if d is not None:
        d.close()


if __name__ == "__main__":
    # CLOSES debug-mode-on and binds-all-interfaces: debug off, localhost only.
    audit.log("store.start", port=5201)
    app.run(host="127.0.0.1", port=5201, debug=False)
