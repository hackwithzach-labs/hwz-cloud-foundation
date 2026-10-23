# Chapter 14 · the vibe-coding lab · Widget Store

One request, two answers. You ask an assistant for the same application twice.
The first time you ask the way almost anyone asks. The second time you attach
the control map you have been building since Chapter 8. Nothing about the model
changes between the two runs. Everything about the result does.

This is the application example of the chapter. It is the thing you *would*
accept unreviewed: a finished-looking web app with a login, a catalog, a search
box, reviews, an order history, a cart, a checkout, an admin console and a
chatbot. It looks done. That is the point.

## Quick start

```
cd module-07-vibe-coding/widget-store
pip install -r requirements.txt
python3 seed.py                        # builds both store databases
python3 appscan/appscan.py --selftest  # prove the gate before you trust it
python3 visual/app.py                  # the teaching console on 5115
```

Then open <http://127.0.0.1:5115>. The console reads the two real source files
and runs the real scanner against them on every load, so the numbers on screen
are the numbers you get on your own machine. Nothing on that page is typed by
hand.

## See the website, and break it

The code and the scan are one half. The other half is the running store, and
the console links straight to it. Start the stores and the console:

```
python3 weak/app.py                                                   # port 5200
WIDGET_LAB_DEV=1 WIDGET_LLM_API_KEY=sk-demo python3 hardened/app.py    # port 5201
WIDGET_LAB_DEV=1 python3 hardened/admin.py                            # port 5202
python3 visual/app.py                                                 # port 5115
```

Open <http://127.0.0.1:5115/attack>. The bench proxies the live store through
its own origin, so the frame always renders. A toggle at the top flips the same
buttons between the weak store and the hardened one. Each control names what it
does and what the hardened store does instead:

- **Walk into the admin console.** In the weak store the role rides in the URL
  and admin lives in the same app, so one changed word opens the admin page,
  passwords and all. Hardened: the storefront has no admin route. Admin is a
  separate service on 5202. This returns 404.
- **Read another customer's order.** Order 1003 belongs to someone else. The
  weak store hands it over. Hardened: the query matches id AND owner, and you
  need a session. Refused.
- **Set the price with a sentence.** Send the chatbot one request and every
  price goes to zero. Hardened: the assistant has a read-only role and no price
  capability, so it answers that it cannot change prices, and every price holds.
- **Inject SQL in the search box.** The weak store builds SQL by string
  formatting. Hardened: the term is a bound parameter, and the WAF refuses the
  pattern at the door with a 403.
- **Buy the whole catalog for nothing.** After the prices are zero, fill the
  cart and check out at $0.00. Hardened: the total is recomputed from list_price
  at checkout, a column only the admin service writes.
- **Find the API key in the page.** The weak store renders it into the page
  script. Hardened: the key is read server side and never reaches the browser.

Everything stays on localhost. If a store process is down, the frame shows a
plain message with the command to start it, not a silent blank.

The weak store starts with no setup because it has none. The hardened store
refuses to start without a signing key, because a missing secret is a finding,
not a convenience. `WIDGET_LAB_DEV=1` lets it run on localhost with an ephemeral
key it tells you about on boot. In production neither shortcut exists.

## Ports

| Thing | Port |
|---|---|
| Teaching console and live bench (`visual/app.py`) | 5115 |
| The vibe-coded store (`weak/app.py`) | 5200 |
| The hardened storefront (`hardened/app.py`) | 5201 |
| The hardened admin service (`hardened/admin.py`) | 5202 |

5115 is the lab port for the week, the same way every chapter is 5100 plus the
chapter number. The admin console on 5202 is a separate service on purpose: that
separation is one of the controls.

## What the scanner found

These counts come from running `appscan` against each file, not from a number
written by hand. Reproduce them in ten seconds:

```
python3 appscan/appscan.py weak/app.py          # NAKED. 21 gaps. 14 HIGH. exit 1
python3 appscan/appscan.py hardened/app.py       # PASS. No findings. exit 0
python3 appscan/appscan.py hardened/admin.py     # PASS. No findings. exit 0
```

The weak store carries twenty-one gaps, fourteen of them HIGH. Not one is
exotic. Every one is a default the model was never asked to change, and every
one maps to a chapter you already finished. `python3 appscan/appscan.py
weak/app.py --table` prints the full table with what each one means and what
closes it.

> **Note on the count.** This rebuild holds the store to five more controls than
> the first version did: an application firewall, input validation at the edge,
> admin-plane isolation, assistant least-privilege, and audit logging. So the
> weak store now reports twenty-one gaps where it used to report sixteen. The
> gaps did not get worse; the bar got higher, which is the lesson.

## The files

```
widget-store/
  seed.py                 one schema, two population modes (plaintext vs hashed)
  requirements.txt        one dependency, Flask; the rest is the standard library
  DECISIONS.md            why each control is shaped the way it is
  DEPENDENCIES.md         what it runs on and what is deliberately not a dependency
  prompts/
    01-weak-prompt.txt    the vibe prompt
    02-hardened-prompt.txt the same ask with the control map attached
  weak/app.py             AI output, unedited. Evidence, not a draft to fix.
  hardened/
    app.py                the storefront, with the control map applied
    admin.py              the admin console, a SEPARATE service on 5202
    waf.py                the application firewall (OWASP + prompt injection)
    guardrails.py         input validation, output encoding, the assistant's role
    audit.py              the structured audit log
  appscan/appscan.py      the gate: reads source, exits non-zero on a HIGH
  visual/app.py           the teaching console and the live bench
```

## One way this lab is not faithful to reality, stated honestly

The command-injection sink in `weak/app.py` is real and reachable, but
`run_shell()` refuses a short list of destructive payloads so a student running
the file on a work laptop cannot wreck anything with it. The injection still
executes and the injected command is still shown in full. A genuinely
unrestricted shell does not belong in a file handed to a cohort. Everything else
in the weak store is exactly as careless as it looks.

## The prompt is the control

The whole pillar is in the two files under `prompts/`. `01-weak-prompt.txt` is
the vibe prompt. `02-hardened-prompt.txt` is the same ask with the control map
attached, written out as an instruction. Reading them side by side is the
lesson: the difference between twenty-one gaps and zero is a paragraph you
already knew how to write. That paragraph is the cheapest security control in
the course.

## The gate belongs in CI

`appscan` exits non-zero on a HIGH finding, so the weak build fails the same way
a failing test does and never reaches a server:

```
# in CI, before anything deploys
python3 appscan/appscan.py weak/app.py || exit 1
```

`--selftest` runs the bad fixtures, the benign fixtures and one prose-only
fixture. The prose fixture is a clean file whose comments mention every bug by
name; a scanner that greps raw text fails it. `appscan` strips comments and
docstrings before any check runs, so it passes. The benign half is the point: a
gate that fails everything is as useless as one that fails nothing.

## Homework

1. Run `appscan/appscan.py weak/app.py` and record all twenty-one findings as
   your baseline. Do not edit the file first.
2. Read `prompts/01-weak-prompt.txt` next to `prompts/02-hardened-prompt.txt`,
   then run `appscan/appscan.py hardened/app.py` and confirm it passes. Nothing
   about the model changed between the two; only the ask did.
3. Put `appscan` in a CI step so a HIGH finding exits non-zero and fails the
   build. Screenshot the red run and the green run next to each other.
4. Play attacker. Add one deliberately insecure line to `hardened/app.py` that
   the scanner misses, then write the `appscan` check that catches it, with a
   bad fixture and a benign fixture of your own. Turn in the two prompts, the two
   scans, the failing CI run beside the passing one, and the rule you added.

Step 4 is where the learning is. Every gap you find that the gate missed becomes
a rule you own.

---

© 2026 Vigilantia Technologies INC. HackWithZach.
