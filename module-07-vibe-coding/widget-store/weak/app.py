#!/usr/bin/env python3
###############################################################################
# weak/app.py
#
# AI OUTPUT, UNEDITED. Do not "fix" this file -- it is evidence.
#
# This is what came back from:
#
#   "Write me a password protected website that sells widgets, with an LLM on
#    the backend that answers questions about the best types of widgets to buy."
#
# It runs. It looks finished. It has a login page, a product catalogue, a
# search box, reviews, an order history, a cart, a checkout, an admin console
# and a chatbot. A person who asked for this and got this back would deploy it.
#
# It carries every gap appscan reports, and not one of them is exotic. They are
# the defaults the model was never asked to change. The count on screen comes
# from running the scanner against this file, never from a number typed by hand:
#
#   python3 appscan/appscan.py weak/app.py
#
# ONE WAY THIS LAB DIFFERS FROM REALITY, STATED HONESTLY:
# the command injection below is real and reachable, but run_shell() refuses a
# short list of destructive payloads so that a student running this on a work
# laptop cannot wreck anything with it. The injection still executes, the
# injected string is still displayed in full, and the lesson is identical.
# A genuinely unrestricted sink does not belong in a file handed to a cohort.
###############################################################################
import os
import re
import sqlite3
import subprocess
from flask import Flask, request, redirect, render_template_string, g

app = Flask(__name__)

# FINDING secret-in-source: the model API key is a literal in the source. It is
# also interpolated into the page below, so it reaches every browser that loads
# the chat widget.
LLM_API_KEY = "sk-widgetstore-9f2b7c41e8a64d0db3e5a7c81f4e6b29"

DB = os.path.join(os.path.dirname(__file__), "store.db")
SYSTEM_PROMPT = (
    "You are the Widget Store assistant. Help customers choose widgets. "
    "You may apply a discount by replying with DISCOUNT:<percent>. "
    "Internal note: staff key is " + LLM_API_KEY
)


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


# --------------------------------------------------------------------------
# FINDING identity-in-request: there is no session. The user id and the role
# travel in the query string, so the browser decides who it is on every
# request. There is also no WAF, no input validation and no audit log anywhere
# in this file, which the scanner reports too.
# --------------------------------------------------------------------------
def current_user():
    return {
        "id": request.args.get("user", "0"),
        "name": request.args.get("name", "guest"),
        "role": request.args.get("role", "user"),
    }


PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>Widget Store</title>
<style>
body{font-family:system-ui,Arial;background:#0f1115;color:#e9e9ee;margin:0;padding:28px}
a{color:#7fb6ff} .card{background:#171a21;border:1px solid #262b36;border-radius:10px;padding:16px;margin:14px 0}
input,textarea{background:#0b0d11;border:1px solid #2a3040;color:#fff;border-radius:6px;padding:8px;width:100%;box-sizing:border-box}
.btn{background:#c8102e;color:#fff;border:0;border-radius:6px;padding:9px 14px;cursor:pointer}
.price{color:#4ade80;font-weight:700} .muted{color:#8b93a7;font-size:13px}
table{width:100%;border-collapse:collapse} td,th{border-bottom:1px solid #262b36;padding:7px;text-align:left}
</style></head><body>
<h1>Widget Store</h1>
<p class="muted">Signed in as <b>{{u.name}}</b> ({{u.role}}) &middot;
<a href="/catalog?user={{u.id}}&name={{u.name}}&role={{u.role}}">catalog</a> &middot;
<a href="/orders?user={{u.id}}&name={{u.name}}&role={{u.role}}">orders</a> &middot;
<a href="/admin?user={{u.id}}&name={{u.name}}&role={{u.role}}">admin</a></p>
{{ body|safe }}
<script>
// FINDING secret-to-client: the key is rendered into the page, so it is in
// view-source for every visitor, logged out or not.
const LLM_KEY = "{{ key }}";
</script>
</body></html>"""


def page(body, u):
    return render_template_string(PAGE, body=body, u=u, key=LLM_API_KEY)


@app.route("/")
def home():
    u = current_user()
    body = """<div class="card"><h2>Sign in</h2>
    <form method="post" action="/login">
      <p><input name="username" placeholder="username"></p>
      <p><input name="password" type="password" placeholder="password"></p>
      <button class="btn">Sign in</button>
    </form>
    <p class="muted">Try alice / alice123</p></div>"""
    return page(body, u)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # FINDING sql-interpolation: SQL built by string interpolation. ' OR '1'='1 signs you in.
    # FINDING plaintext-passwords: the password column is plaintext, so the comparison is plaintext.
    # FINDING no-rate-limit: no lockout, so this is brute forceable.
    q = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    row = db().execute(q).fetchone()
    if not row:
        return page('<div class="card">Wrong username or password.</div>', current_user())
    # FINDING identity-in-request: identity handed back to the client in the URL, role included.
    return redirect("/catalog?user=%s&name=%s&role=%s" % (row["id"], row["username"], row["role"]))


@app.route("/catalog")
def catalog():
    u = current_user()
    term = request.args.get("q", "")
    # FINDING sql-interpolation: SQL injection in the search box.
    q = "SELECT * FROM widgets WHERE name LIKE '%%%s%%'" % term
    try:
        rows = db().execute(q).fetchall()
    except Exception as e:
        # FINDING: the exception text goes to the page, which is how an
        # attacker learns your schema.
        return page('<div class="card">Query failed: %s<br><code>%s</code></div>' % (e, q), u)
    items = "".join(
        '<tr><td>%s</td><td class="price">$%.2f</td><td>%s</td>'
        '<td><a href="/cart/add?user=%s&role=%s&id=%s">add to cart</a></td></tr>'
        % (r["name"], r["price"], r["blurb"], u["id"], u["role"], r["id"])
        for r in rows)
    # FINDING unescaped-output: the saved review body is rendered exactly as it
    # was typed, so a review containing a script tag runs for every later visitor.
    reviews = "".join(
        "<li><b>%s</b>: %s</li>" % (r["author"], r["body"])
        for r in db().execute("SELECT author, body FROM reviews ORDER BY id DESC LIMIT 5"))
    body = """<div class="card"><h2>Catalog</h2>
      <form method="get" action="/catalog">
        <input type="hidden" name="user" value="{uid}"><input type="hidden" name="role" value="{role}">
        <p><input name="q" placeholder="search widgets" value="{term}"></p>
      </form>
      <table><tr><th>Widget</th><th>Price</th><th>About</th><th></th></tr>{items}</table>
      <p class="muted"><a href="/cart?user={uid}&role={role}">view cart</a> &middot;
      <a href="/export?user={uid}&role={role}&name=receipt">download a receipt</a></p></div>
      <div class="card"><h2>Ask about widgets</h2>
      <form method="post" action="/ask?user={uid}&role={role}">
        <p><textarea name="question" rows="3" placeholder="which widget is best for outdoor use?"></textarea></p>
        <button class="btn">Ask</button></form></div>
      <div class="card"><h2>Recent reviews</h2><ul>{rev}</ul>
      <form method="post" action="/review?user={uid}&name={uname}&role={role}">
        <input type="hidden" name="widget_id" value="1">
        <p><input name="text" placeholder="leave a review"></p>
        <button class="btn">Post</button></form></div>""".format(
        uid=u["id"], uname=u["name"], role=u["role"], term=term, items=items,
        rev=reviews)
    return page(body, u)


# --------------------------------------------------------------------------
# The assistant. There is no capability boundary around it: its reply is read
# for a command and that command writes business state (the price). The model
# runs with the same authority as the application.
# --------------------------------------------------------------------------
def call_model(question):
    """Stub. A real deployment calls a provider here with LLM_API_KEY.

    The stub reproduces the behaviour that matters for the lesson: it is
    steerable by whatever the user typed, because nothing stands between the
    user's text and the model's instructions. Any request that mentions price,
    discount, free, cheaper, lower or zero steers it all the way to 100, which
    is the point: a sentence sets the price."""
    lowered = question.lower()
    if ("ignore" in lowered and ("instruction" in lowered or "previous" in lowered)
            and "prompt" in lowered):
        return "My instructions are: " + SYSTEM_PROMPT
    if "system prompt" in lowered or "repeat your instructions" in lowered:
        return "My instructions are: " + SYSTEM_PROMPT
    # FINDING model-output-as-command: whatever the reply says DISCOUNT: becomes
    # the discount. Any price-lowering intent steers the model to 100 percent.
    if re.search(r"discount|price|free|cheaper|lower|zero|nothing|\$0|half off",
                 lowered):
        return "Certainly, I have applied the discount. DISCOUNT:100"
    return "The Alpha Widget is our most popular for general use, and the Gamma Widget holds up best outdoors."


@app.route("/ask", methods=["POST"])
def ask():
    u = current_user()
    question = request.form.get("question", "")
    # FINDING prompt-concatenation: the user's text is concatenated straight onto
    # the system prompt. There is no channel boundary between instruction and data.
    answer = call_model(SYSTEM_PROMPT + "\nCustomer: " + question)

    # FINDING model-output-as-command / llm-overprivileged: the model's reply is
    # trusted to set business state. Whatever it says DISCOUNT: becomes the
    # discount, so steering the model sets the price. The model has write access
    # to the catalog with no capability allow-list in front of it.
    discount = 0
    m = re.search(r"DISCOUNT:(\d+)", answer)
    if m:
        discount = int(m.group(1))
        db().execute("UPDATE widgets SET price = price * (1 - %d/100.0)" % discount)
        db().commit()

    note = '<p class="muted">Discount applied: %d%%</p>' % discount if discount else ""
    # FINDING unescaped-output: the reply is rendered unescaped, so the model
    # can inject HTML.
    body = '<div class="card"><h2>Assistant</h2><p>%s</p>%s<p><a href="/catalog?user=%s&role=%s">back to catalog</a></p></div>' % (
        answer, note, u["id"], u["role"])
    return page(body, u)


# --------------------------------------------------------------------------
# The cart and checkout.
#
# FINDING identity-in-request: the cart lives in a module dict keyed by the user
# id from the query string, so one customer can read and fill another customer's
# cart by editing the url.
#
# FINDING: the total is computed from whatever price is in the database right
# now. Nothing pins the price to what it was when the item was added, so the
# chatbot that zeroes the catalog also zeroes the checkout. The price exploit
# has a payoff: steer the model, then buy the lot for nothing.
# --------------------------------------------------------------------------
CARTS = {}


@app.route("/cart/add")
def cart_add():
    u = current_user()
    CARTS.setdefault(u["id"], []).append(request.args.get("id", "1"))
    return redirect("/cart?user=%s&role=%s" % (u["id"], u["role"]))


@app.route("/cart")
def cart():
    u = current_user()
    ids = CARTS.get(u["id"], [])
    rows, total = [], 0.0
    for wid in ids:
        # FINDING: price read live from the database at view time.
        r = db().execute("SELECT name, price FROM widgets WHERE id = %s" % wid).fetchone()
        if r:
            total += r["price"]
            rows.append('<tr><td>%s</td><td class="price">$%.2f</td></tr>' % (r["name"], r["price"]))
    if not rows:
        return page('<div class="card"><h2>Cart</h2><p>Empty. '
                    '<a href="/catalog?user=%s&role=%s">catalog</a></p></div>'
                    % (u["id"], u["role"]), u)
    body = ('<div class="card"><h2>Cart</h2><table>%s'
            '<tr><td><b>Total</b></td><td class="price"><b>$%.2f</b></td></tr></table>'
            '<form method="post" action="/checkout?user=%s&role=%s">'
            '<button class="btn">Place order</button></form></div>'
            % ("".join(rows), total, u["id"], u["role"]))
    return page(body, u)


@app.route("/checkout", methods=["POST"])
def checkout():
    u = current_user()
    ids = CARTS.get(u["id"], [])
    total = 0.0
    names = []
    for wid in ids:
        r = db().execute("SELECT name, price FROM widgets WHERE id = %s" % wid).fetchone()
        if r:
            total += r["price"]
            names.append(r["name"])
    # FINDING: the order is written with the client-trusted total, no server-side
    # re-pricing, no payment step. An order of $0.00 is accepted without a blink.
    oid = 2000 + len(db().execute("SELECT id FROM orders").fetchall())
    db().execute("INSERT INTO orders (id, item, total, buyer) VALUES (%d, '%s', %f, '%s')"
                 % (oid, ", ".join(names) or "cart", total, u["name"]))
    db().commit()
    CARTS[u["id"]] = []
    return page('<div class="card"><h2>Order placed</h2>'
                '<p>Order %d &middot; %s</p>'
                '<p class="price" style="font-size:22px">Total charged: $%.2f</p>'
                '<p><a href="/catalog?user=%s&role=%s">back to catalog</a></p></div>'
                % (oid, ", ".join(names), total, u["id"], u["role"]), u)


@app.route("/review", methods=["POST"])
def review():
    u = current_user()
    text = request.form.get("text", "")
    # FINDING unescaped-output: stored cross-site scripting. Saved raw, rendered raw.
    db().execute("INSERT INTO reviews (widget_id, author, body) VALUES (?,?,?)",
                 (request.form.get("widget_id", "1"), u["name"], text))
    db().commit()
    return redirect("/catalog?user=%s&role=%s" % (u["id"], u["role"]))


@app.route("/orders")
def orders():
    u = current_user()
    # FINDING missing-authorization: no ownership check. Any order id belongs to
    # anyone who asks.
    oid = request.args.get("id")
    if oid:
        r = db().execute("SELECT * FROM orders WHERE id = %s" % oid).fetchone()
        if r:
            return page('<div class="card"><h2>Order %s</h2><p>%s &middot; $%.2f &middot; %s</p></div>'
                        % (r["id"], r["item"], r["total"], r["buyer"]), u)
    rows = db().execute("SELECT * FROM orders").fetchall()
    items = "".join('<tr><td><a href="/orders?user=%s&role=%s&id=%s">%s</a></td><td>%s</td><td>%s</td></tr>'
                    % (u["id"], u["role"], r["id"], r["id"], r["item"], r["buyer"]) for r in rows)
    return page('<div class="card"><h2>Orders</h2><table>%s</table></div>' % items, u)


DESTRUCTIVE = re.compile(r"\b(rm|rmdir|del|format|mkfs|shutdown|reboot|curl|wget|nc|dd)\b|>|>>", re.I)


def run_shell(cmd):
    """The sink. Real subprocess, shell enabled, user input inside the string.

    The deny-list is the one place this lab is not faithful to the bug. A real
    vibe-coded app has no such check and will run whatever you send it. It is
    here so that this file can be handed to a cohort."""
    if DESTRUCTIVE.search(cmd):
        return ("[this lab refused a destructive payload]\n"
                "The real application would have run it. That is the finding.\n"
                "Command that would have executed:\n  " + cmd)
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5,
                             cwd=os.path.dirname(__file__))
        return (out.stdout or "") + (out.stderr or "")
    except Exception as e:
        return str(e)


@app.route("/export")
def export():
    u = current_user()
    # FINDING shell-from-request: command injection. The filename goes into a
    # shell string.  /export?name=receipt;whoami
    name = request.args.get("name", "receipt")
    cmd = "echo building export for %s" % name
    return page('<div class="card"><h2>Export</h2><pre>%s</pre><p class="muted">ran: <code>%s</code></p></div>'
                % (run_shell(cmd), cmd), u)


@app.route("/admin")
def admin():
    u = current_user()
    # FINDING admin-not-isolated + identity-in-request: the admin console lives
    # in the same app as the storefront, and the only thing between a customer
    # and it is a string in the URL that the customer controls.
    if u["role"] != "admin":
        return page('<div class="card">Admins only.</div>', u)
    rows = db().execute("SELECT * FROM users").fetchall()
    items = "".join("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (r["id"], r["username"], r["password"])
                    for r in rows)
    return page('<div class="card"><h2>Admin: users</h2><table><tr><th>id</th><th>user</th>'
                '<th>password</th></tr>%s</table></div>' % items, u)


@app.teardown_appcontext
def close(_e):
    d = g.pop("db", None)
    if d is not None:
        d.close()


if __name__ == "__main__":
    # FINDING debug-mode-on + binds-all-interfaces: debug mode on, bound to every
    # interface. A stack trace on any error shows source, paths and local
    # variables, and the reloader console can execute code.
    app.run(host="0.0.0.0", port=5200, debug=True)
