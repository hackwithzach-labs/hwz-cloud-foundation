#!/usr/bin/env python3
"""guardrails.py -- input validation, output encoding, and the assistant's
capability boundary.

CLOSES: no-input-validation (every request value is validated before use),
unescaped-output (one escape helper used at every render), llm-overprivileged
(the assistant is given a named role with an explicit allow-list and no write
authority).

Three ideas, one file, because they are the same idea at three points: never
trust a value until you have constrained it, whether the value came from a
form, from the model, or from the model wanting to act.
"""
from markupsafe import escape
from werkzeug.exceptions import BadRequest


# --------------------------------------------------------------------------
# Input validation. Every request value is pulled through one of these, so a
# value is typed and bounded before it reaches a query or a template. A missing
# or malformed value is a 400, not a stack trace.
# --------------------------------------------------------------------------
def require_int(value, field, lo=None, hi=None):
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise BadRequest("%s must be a whole number." % field)
    if lo is not None and n < lo:
        raise BadRequest("%s is out of range." % field)
    if hi is not None and n > hi:
        raise BadRequest("%s is out of range." % field)
    return n


def clean_str(value, field, maxlen=200, allow_empty=True):
    if value is None:
        value = ""
    value = str(value)
    if len(value) > maxlen:
        raise BadRequest("%s is too long." % field)
    if not allow_empty and not value.strip():
        raise BadRequest("%s is required." % field)
    return value


def encode(value):
    """The one output-encoding helper. Everything user or model derived passes
    through this before it reaches markup, so there is no un-escaped path."""
    return escape(value)


# --------------------------------------------------------------------------
# The assistant's role. This is least privilege expressed as code: the
# assistant is an identity with a capability allow-list, and pricing, orders,
# users and shell are simply not on it. The model's reply is data to display,
# never a command to run, so there is no DISCOUNT: marker to parse and no write
# for a sentence to reach.
# --------------------------------------------------------------------------
ASSISTANT_ROLE = "assistant-readonly"
ASSISTANT_CAPABILITIES = frozenset({
    "catalog.read",     # it may describe widgets from the catalog
    "answer.text",      # it may return text to display
})
# Everything the weak assistant could reach, named here as explicitly denied so
# the boundary is readable: pricing, discounts, orders, users, shell, secrets.
ASSISTANT_DENIED = frozenset({
    "price.write", "discount.apply", "order.write", "user.read",
    "shell.exec", "secret.read",
})


def assistant_can(capability):
    """The allow-list check. The assistant can only do what is on the list."""
    return capability in ASSISTANT_CAPABILITIES


def safe_answer(model_reply):
    """Treat the model's reply as display text. It is encoded, and any command
    marker it tries to carry is inert because nothing downstream reads it. This
    is the output guardrail: the reply can be shown, it cannot act."""
    return encode(model_reply)
