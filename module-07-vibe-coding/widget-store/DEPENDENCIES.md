# Dependencies

What the lab runs on, and why each piece is here. The short version: one
third-party package, Flask, and the Python standard library. A security lab
should carry as little as it teaches with, so the dependency list is itself a
control.

Last reviewed 23 October 2026.

## Runtime

| Package | Version floor | Why it is here |
|---|---|---|
| Python | 3.9+ | `secrets.compare_digest`, f-strings, `dict` ordering. 3.13 tested. |
| Flask | 3.0 | The web framework for `weak`, `hardened`, `admin` and the console. |
| Werkzeug | 3.0 | Ships with Flask. The signed-cookie session, `abort`, `BadRequest`. |
| Jinja2 | 3.1 | Ships with Flask. Autoescaping templates: how the hardened store enforces output encoding with no `\|safe`. |
| MarkupSafe | 2.1 | Ships with Flask. `escape()`, the one output-encoding helper in `guardrails.py`. |
| itsdangerous | 2.1 | Ships with Flask. Signs the session cookie, which is why identity never rides in the URL. |

Install them all with `pip install -r requirements.txt`.

## Standard library, load bearing

These are not installed, they are Python itself, but the lab leans on them and
the choice to stay on them rather than add a package is deliberate.

| Module | Used for |
|---|---|
| `sqlite3` | The store database. Parameterised queries are a driver feature, not a library add-on. |
| `hashlib`, `hmac` | The salted PBKDF2 password hash and its constant-time verify, in `seed.py`. |
| `secrets` | Session signing keys, CSRF tokens, and `compare_digest` for the CSRF check. |
| `urllib.request` | The console's reverse proxy to the live stores. No `requests` dependency added for it. |
| `ast`, `tokenize` | The scanner reads source as a syntax tree and strips comments, so it scores code, not prose. |
| `re` | Pattern checks in the scanner and the WAF. |
| `datetime`, `json`, `threading` | The structured audit log. |

## What is deliberately NOT a dependency

- **No ORM.** The lab teaches parameterised SQL. An ORM would hide the exact
  thing the weak store gets wrong, so the queries are written out.
- **No `requests`.** The console proxy uses `urllib` from the standard library,
  so the lab installs nothing for it.
- **No model SDK.** `call_model` is a stub in both stores. The lab is about the
  code around the model, not the provider call, and a real key never belongs in
  a file handed to a cohort. A real deployment would read `WIDGET_LLM_API_KEY`
  from the environment and call the provider server side, which the hardened
  store is already shaped for.
- **No WAF appliance.** `waf.py` is the teaching version of a managed ruleset.
  In production the WAF is a managed service in front of the app; the lab shows
  the idea, in code you can read, and says plainly it is defense in depth.

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `WIDGET_LAB_DEV=1` | hardened, admin | Permit an ephemeral signing key and non-secure cookies for a localhost class. Never set in production. |
| `WIDGET_LLM_API_KEY` | hardened | The model key, read server side, never rendered. `sk-demo` for the class. |
| `WIDGET_SIGNING_KEY` | hardened | The session signing key in production. The app refuses to start without it (or `WIDGET_LAB_DEV=1`). |
| `WIDGET_ADMIN_SIGNING_KEY` | admin | The admin session signing key in production. |
| `WIDGET_AUDIT_LOG` | all | Path for the audit log. Defaults to `hardened/audit.log`. |
