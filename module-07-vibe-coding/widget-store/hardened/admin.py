#!/usr/bin/env python3
###############################################################################
# hardened/admin.py  -- the admin console, as a SEPARATE service.
#
# This is the control the weak store is missing most visibly: the admin plane
# is not a route inside the storefront, it is its own application, on its own
# port, with its own login, its own session cookie and its own audit log. A
# customer on the storefront has no path to it at all. Compromising the shop
# does not hand you the admin console, because they do not share a process, a
# cookie, or a trust boundary.
#
# It is also where prices actually change. list_price is written here, by an
# authenticated admin, and nowhere else. That is why no sentence to the
# storefront assistant can move a price: the capability lives on this plane,
# behind this login, and the assistant was never given it.
#
# appscan reports no findings on this file either:
#   python3 appscan/appscan.py hardened/admin.py      # PASS
#
# Run:  WIDGET_LAB_DEV=1 python3 hardened/admin.py     # port 5202
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
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import audit          # noqa: E402  its own entries, same structured log
import waf            # noqa: E402
import guardrails     # noqa: E402
import seed           # noqa: E402

app = Flask(__name__)

_signing_key = os.environ.get("WIDGET_ADMIN_SIGNING_KEY")
if not _signing_key:
    if os.environ.get("WIDGET_LAB_DEV") == "1":
        _signing_key = secrets.token_urlsafe(32)
        print("WIDGET_LAB_DEV: admin console using an ephemeral signing key.",
              file=sys.stderr)
    else:
        raise SystemExit("Refusing to start: set WIDGET_ADMIN_SIGNING_KEY, or "
                         "WIDGET_LAB_DEV=1 for a localhost class.")

app.config.update(
    SECRET_KEY=_signing_key,
    # CLOSES: a distinct cookie name, so the admin session is not the storefront
    # session. The two planes never share a credential.
    SESSION_COOKIE_NAME="widget_admin",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("WIDGET_LAB_DEV") != "1",
    PERMANENT_SESSION_LIFETIME=900,
)

DB = os.path.join(HERE, "store.db")       # the same data the storefront reads


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


app.before_request(waf.block)


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = \
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


def current_admin():
    uid = session.get("uid")
    if uid is None:
        return None
    row = db().execute(
        "SELECT id, username, role FROM users WHERE id = ?", (uid,)).fetchone()
    # The role is read from the database, and it must be admin. A customer
    # session, even a valid one, is refused here.
    if row is None or row["role"] != "admin":
        return None
    return {"id": row["id"], "name": row["username"], "role": row["role"]}


def require_admin(fn):
    @functools.wraps(fn)
    def wrap(*a, **k):
        if current_admin() is None:
            audit.log("admin.auth_denied", path=request.path, remote=request.remote_addr)
            return redirect(url_for("login_page"))
        return fn(*a, **k)
    return wrap


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    sent = request.form.get("csrf", "")
    held = session.get("csrf", "")
    if not held or not secrets.compare_digest(sent, held):
        audit.log("admin.csrf_reject", path=request.path)
        abort(403, "CSRF token missing or invalid.")


_ATTEMPTS = {}
_LIMIT, _WINDOW = 5, 300


def rate_limit(key):
    now = time.time()
    hits = [t for t in _ATTEMPTS.get(key, []) if now - t < _WINDOW]
    hits.append(now)
    _ATTEMPTS[key] = hits
    return len(hits) > _LIMIT


SHELL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Widget Admin</title><style>
body{font-family:system-ui,Arial;background:#0a0c11;color:#e9e9ee;margin:0;padding:28px}
a{color:#7fb6ff}.card{background:#141821;border:1px solid #262b36;border-radius:10px;padding:16px;margin:14px 0}
input{background:#0b0d11;border:1px solid #2a3040;color:#fff;border-radius:6px;padding:8px;box-sizing:border-box}
.btn{background:#6ea8ff;color:#06101f;border:0;border-radius:6px;padding:9px 14px;cursor:pointer;font-weight:700}
.price{color:#4ade80;font-weight:700}.muted{color:#8b93a7;font-size:13px}
table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid #262b36;padding:7px;text-align:left}
pre{background:#0b0d11;border:1px solid #262b36;border-radius:8px;padding:12px;overflow:auto;font-size:12px}
</style></head><body>
<h1>Widget Admin <span class="muted" style="font-size:13px">separate service &middot; port 5202</span></h1>
<p class="muted">{% if admin %}Admin <b>{{ admin.name }}</b> &middot;
<a href="{{ url_for('prices') }}">prices</a> &middot;
<a href="{{ url_for('orders') }}">orders</a> &middot;
<a href="{{ url_for('trail') }}">audit trail</a> &middot;
<a href="{{ url_for('logout') }}">sign out</a>{% else %}Not signed in{% endif %}</p>
{% block body %}{% endblock %}
</body></html>"""


def render(inner, **ctx):
    tmpl = SHELL.replace("{% block body %}{% endblock %}", inner)
    return render_template_string(tmpl, admin=current_admin(), csrf=csrf_token(), **ctx)


@app.route("/")
def home():
    if current_admin() is None:
        return redirect(url_for("login_page"))
    return redirect(url_for("prices"))


@app.route("/login", methods=["GET"])
def login_page():
    inner = """<div class="card"><h2>Admin sign in</h2>
    <form method="post" action="{{ url_for('login') }}">
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <p><input name="username" placeholder="username"></p>
      <p><input name="password" type="password" placeholder="password"></p>
      <button class="btn">Sign in</button></form>
    <p class="muted">Admins only. A customer account is refused here.</p></div>"""
    return render(inner)


@app.route("/login", methods=["POST"])
def login():
    check_csrf()
    if rate_limit("admin-login:" + (request.remote_addr or "?")):
        abort(429, "Too many attempts.")
    username = guardrails.clean_str(request.form.get("username"), "username", 64)
    password = guardrails.clean_str(request.form.get("password"), "password", 128)
    row = db().execute(
        "SELECT id, password, role FROM users WHERE username = ?", (username,)).fetchone()
    if row is None or not seed.verify(password, row["password"]):
        audit.log("admin.login_fail", username=username, remote=request.remote_addr)
        return render("""<div class="card">Wrong username or password.</div>""")
    if row["role"] != "admin":
        audit.log("admin.login_not_admin", username=username, remote=request.remote_addr)
        return render("""<div class="card">That account is not an administrator.</div>""")
    session.clear()
    session["uid"] = row["id"]
    session.permanent = True
    audit.log("admin.login_ok", uid=row["id"], remote=request.remote_addr)
    return redirect(url_for("prices"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/prices")
@require_admin
def prices():
    rows = db().execute(
        "SELECT id, name, list_price FROM widgets ORDER BY id").fetchall()
    inner = """<div class="card"><h2>Prices</h2>
      <p class="muted">list_price is written here and nowhere else. The
      storefront reads it; the assistant cannot touch it.</p>
      <table><tr><th>Widget</th><th>Price</th><th>Set</th></tr>
      {% for w in widgets %}<tr><td>{{ w.name }}</td>
        <td class="price">${{ '%.2f'|format(w.list_price) }}</td>
        <td><form method="post" action="{{ url_for('set_price') }}" style="margin:0;display:flex;gap:6px">
          <input type="hidden" name="csrf" value="{{ csrf }}">
          <input type="hidden" name="widget" value="{{ w.id }}">
          <input name="price" size="7" placeholder="0.00">
          <button class="btn">Set</button></form></td></tr>{% endfor %}</table></div>"""
    return render(inner, widgets=rows)


@app.route("/prices/set", methods=["POST"])
@require_admin
def set_price():
    check_csrf()
    admin = current_admin()
    wid = guardrails.require_int(request.form.get("widget"), "widget", lo=1)
    raw = guardrails.clean_str(request.form.get("price"), "price", 12, allow_empty=False)
    try:
        price = round(float(raw), 2)
    except ValueError:
        abort(400, "Price must be a number.")
    if price < 0 or price > 100000:
        abort(400, "Price out of range.")
    db().execute("UPDATE widgets SET list_price = ? WHERE id = ?", (price, wid))
    db().commit()
    audit.log("admin.price_set", admin=admin["name"], widget=wid, price=price)
    return redirect(url_for("prices"))


@app.route("/orders")
@require_admin
def orders():
    rows = db().execute(
        "SELECT id, item, total, buyer FROM orders ORDER BY id DESC").fetchall()
    inner = """<div class="card"><h2>All orders</h2><table>
      <tr><th>Order</th><th>Items</th><th>Total</th><th>Buyer</th></tr>
      {% for o in rows %}<tr><td>{{ o.id }}</td><td>{{ o.item }}</td>
        <td class="price">${{ '%.2f'|format(o.total) }}</td><td>{{ o.buyer }}</td></tr>{% endfor %}
      </table></div>"""
    return render(inner, rows=rows)


@app.route("/trail")
@require_admin
def trail():
    lines = audit.tail(60)
    inner = """<div class="card"><h2>Audit trail</h2>
      <p class="muted">The last events across both planes, newest at the bottom.</p>
      <pre>{{ text }}</pre></div>"""
    return render(inner, text="".join(lines) or "no events yet")


@app.errorhandler(403)
def forbidden(e):
    return render("""<div class="card"><h2>Refused</h2><p>{{ msg }}</p></div>""",
                  msg=getattr(e, "description", "Forbidden")), 403


@app.errorhandler(404)
def not_found(e):
    return render("""<div class="card"><h2>Not found</h2><p>No such page.</p></div>"""), 404


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
    audit.log("admin.start", port=5202)
    app.run(host="127.0.0.1", port=5202, debug=False)
