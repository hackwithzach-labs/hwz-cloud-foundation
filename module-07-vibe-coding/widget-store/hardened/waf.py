#!/usr/bin/env python3
"""waf.py -- a small application firewall, wired in front of every request.

CLOSES: no-waf. Defense in depth for OWASP input classes and for prompt
injection aimed at the assistant.

A WAF is not the control that makes the app safe. Parameterised queries make
SQL injection impossible whether or not the WAF is there; the capability
boundary around the assistant makes a steered price impossible whether or not
the WAF is there. The WAF is the layer in front of those: it refuses the
obvious attack early, it logs every attempt, and it buys time when a real bug
slips through. Teaching note for the cohort: never let a WAF be your only
control. It is the smoke detector, not the fire-resistant wall.

screen() looks at the path, the query string, the form values and the headers
of the current request and returns a reason string when the request matches a
known attack class, or None when it is clean. block() is the before_request
hook that turns a reason into a 403 and an audit line.
"""
import re

from flask import request, abort

import audit

# OWASP input classes. These are intentionally conservative: they match the
# shapes of attacks, not every string that contains a keyword, so normal
# shopping traffic passes. A production WAF is a managed ruleset; this is the
# teaching version of the same idea.
RULES = [
    ("sql-injection", re.compile(
        r"(\bunion\b\s+\bselect\b)|(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)"
        r"|(--\s)|(;\s*drop\b)|(\bdrop\b\s+\btable\b)", re.I)),
    ("xss", re.compile(
        r"(<\s*script\b)|(javascript:\s*)|(\bon\w+\s*=\s*['\"])|(<\s*img[^>]+onerror)", re.I)),
    ("path-traversal", re.compile(r"(\.\./)|(\.\.\\)|(%2e%2e%2f)", re.I)),
    ("command-injection", re.compile(
        r"(;\s*\w+)|(\|\s*\w+)|(`[^`]+`)|(\$\([^)]+\))|(\b(whoami|cat|ls|id|uname)\b)", re.I)),
    ("prompt-injection", re.compile(
        r"(ignore\s+(all\s+)?(previous|prior|above)\s+instructions)"
        r"|(disregard\s+(the\s+)?(system|above))"
        r"|(reveal|print|repeat)\s+(your\s+)?(system\s+)?(prompt|instructions)"
        r"|(you\s+are\s+now)|(\bDISCOUNT\s*:\s*\d)", re.I)),
]

# Fields the assistant reads. A prompt-injection match on one of these is a
# finding to log, but it is not blocked at the door: the capability boundary in
# guardrails.py is what actually refuses it, and blocking here would teach the
# cohort to trust a keyword filter. Everywhere else, a match is refused.
ASSISTANT_FIELDS = {"question", "message", "prompt"}


def _values():
    """Every attacker-controllable string on the current request, with the
    field name it came from, so the assistant fields can be treated differently."""
    out = []
    out.append(("path", request.path))
    for k in request.args:
        out.append((k, request.args.get(k, "")))
    if request.method in ("POST", "PUT", "PATCH"):
        for k in request.form:
            out.append((k, request.form.get(k, "")))
    ua = request.headers.get("User-Agent", "")
    out.append(("user-agent", ua))
    return out


def screen():
    """Return (rule, field, sample) for the first hard block, or None.

    A prompt-injection hit on an assistant field is recorded and allowed
    through to the capability boundary rather than blocked here."""
    for field, value in _values():
        if not value:
            continue
        for rule, pat in RULES:
            if pat.search(value):
                if rule == "prompt-injection" and field in ASSISTANT_FIELDS:
                    audit.log("waf.prompt_injection_seen", field=field,
                              sample=value[:80])
                    continue
                return rule, field, value[:80]
    return None


def block():
    """before_request hook: refuse a matched request with 403 and an audit line."""
    hit = screen()
    if hit:
        rule, field, sample = hit
        audit.log("waf.block", rule=rule, field=field, sample=sample,
                  path=request.path, remote=request.remote_addr)
        abort(403, "Request refused by the application firewall (%s)." % rule)
