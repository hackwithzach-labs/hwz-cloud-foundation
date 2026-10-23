# Decision log

How the widget-store lab is built and why. One short record per decision, in
the order the decisions were made, so the next person can see the reasoning and
not just the result. This is the documentation requirement from the control map:
the code says what, this file says why.

Last rebuilt 23 October 2026.

---

## 1. Two stores, one request, one data model

The lab is one prompt answered twice: `weak/app.py` is the vibe-coded answer,
`hardened/app.py` is the same ask with the control map attached. Both read the
same schema from `seed.py`, so every attack on one has an exact counterpart on
the other. The weak store is held together deliberately: it is evidence, not a
draft to fix.

## 2. The weak store stays naive on purpose

It uses identity in the URL, string-interpolated SQL, plaintext passwords, a
shell sink, a model reply parsed as a command, and admin mixed into the
storefront. These are not caricatures. They are the defaults a model emits when
the ask does not forbid them. The one concession to safety is `run_shell()`,
which refuses a short deny-list of destructive payloads so the file is safe to
hand to a cohort. The injection still executes and is shown in full.

## 3. The hardened store is split into small modules

`app.py` is the storefront. `admin.py` is a separate service. `waf.py`,
`guardrails.py` and `audit.py` are the three cross-cutting controls, each in its
own file so the control is readable on its own and the scanner can see it wired
in. The modules import as siblings (`import audit`), because the lab runs each
app as a plain script with its own directory on the path, the same convention
as the rest of the course.

## 4. Admin is a separate service, not a separate route

**Decision:** the admin console is its own Flask app on port 5202, with its own
login, its own session cookie name (`widget_admin`), and its own audit entries.

**Why:** a route guard in the same process shares a runtime and a cookie with
the storefront, so a storefront compromise reaches it. A separate service does
not. This is the control the weak store misses most visibly: in the weak store
one changed word in the URL opens admin; in the hardened store the storefront
has no admin route to reach at all, and the separate service refuses a customer
session even when it is valid. This was the architecture chosen deliberately
over a same-app `/admin` path for exactly that isolation.

## 5. Pricing authority lives only on the admin plane

`list_price` is written by `admin.py` and read everywhere else. The storefront
reads it; the assistant cannot touch it. This is what makes the weak store's
free-checkout attack impossible on the hardened side: there is no code path from
a customer, or from the model, to a price. The capability lives behind the admin
login, and the assistant was never given it.

## 6. The assistant gets a named read-only role

**Decision:** `guardrails.ASSISTANT_ROLE` with an explicit capability allow-list
(`catalog.read`, `answer.text`) and a named denied-list (pricing, orders, users,
shell, secrets).

**Why:** the weak store's price-by-sentence bug is not really a prompt bug, it is
a privilege bug. The model's reply was trusted to set state because the code
around it had the authority to set state. Least privilege expressed as code
removes the authority, so there is nothing for a steered reply to reach. The
instruction and the user text are passed as separate arguments, and the reply is
display text, so there is no marker to parse either.

## 7. A WAF, clearly labelled as defense in depth

**Decision:** `waf.py` screens every request for the OWASP input classes and for
prompt injection, before any view runs, and logs every hit.

**Why:** the teaching risk with a WAF is that students treat it as the control.
It is not. The parameterised query makes SQL injection impossible with or without
it; the capability boundary makes a steered price impossible with or without it.
The WAF is the layer in front: it refuses the obvious attack early and buys time
when a real bug slips through. Prompt-injection hits on the assistant's own input
field are logged but passed through to the capability boundary rather than
keyword-blocked, so the lab does not teach that a keyword filter is security.

## 8. Input validation at the edge, output encoding at the sink

`guardrails.py` holds the validators (`require_int`, `clean_str`) and the one
output-encoding helper (`encode`). Every request value is typed and bounded
before use, and every rendered value is escaped at the point of render. The
hardened templates use Jinja autoescaping with no `|safe`, so there is no
un-escaped path by construction.

## 9. Structured audit logging, file and stdout

`audit.py` writes one JSON line per security event to a file and to stderr, with
no network dependency. A log that needs a service to be up is a log you lose
first. The admin console reads the tail of it, so the trail is visible in the
product, not only in a file.

## 10. The console reverse-proxies the live stores

**Decision:** the bench at `/attack` proxies the stores through its own origin
(`/live/weak/...`, `/live/hard/...`) instead of framing another port directly.

**Why:** the earlier bench put the store in a cross-origin iframe pointed at
`127.0.0.1:5200`. If the store process was not up, or the browser declined the
frame, the panel went blank with no error, which is why the attack did not work
for some people. Proxying through the same origin makes the frame always render,
makes the frame's address bar readable, and lets a down store show a plain
"start it" message instead of a silent blank. Root-absolute links in the store
HTML are rewritten to the proxy prefix so every link and form keeps working.

## 11. The assistant's demo endpoint carries no CSRF token

`/ask` on the hardened store is read-only and changes no state, so it does not
require a CSRF token. CSRF protection guards the state-changing POSTs (login,
cart, checkout, review). This also lets the bench drive the assistant demo
against the hardened store and show the refusal, rather than a token error.

## 12. The scanner grew five checks for the new controls

`appscan` gained `no-waf`, `no-input-validation`, `admin-not-isolated`,
`llm-overprivileged` (all HIGH) and `no-audit-log` (MEDIUM). The weak store now
reports more gaps than it did before the rebuild, because the lab now holds it
to five more controls. Each new rule has a bad fixture and a benign fixture in
the self-test, so the gate still proves it fires on its bug and on nothing else.
The counts on screen come from running the scanner, never from a number typed by
hand.
