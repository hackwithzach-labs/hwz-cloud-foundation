#!/usr/bin/env python3
"""audit.py -- the structured audit log the hardened store writes to.

CLOSES: no-audit-log, no-model-audit-log.

Every security-relevant event becomes one JSON line: who, what, when, from
where, and the outcome. One line per event, machine readable, so a steering
attempt that succeeded and one that failed do not look identical afterwards.
This is the Chapter 3 detection idea applied to an application: the evidence
is the point, everything after it is plumbing.

The weak store has nothing here. The gap between nothing and this is the
finding. It is deliberately boring: a file and stdout, no agent, no network,
because a log that depends on a service being up is a log you lose first.
"""
import datetime
import json
import os
import sys
import threading

_LOCK = threading.Lock()
_LOGFILE = os.environ.get("WIDGET_AUDIT_LOG",
                          os.path.join(os.path.dirname(__file__), "audit.log"))


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def log(event, request_id=None, **fields):
    """Write one audit line. Values are coerced to strings so a surprise type
    never breaks the log, and the password, the session key and anything that
    looks like a secret are never passed in by the callers below."""
    record = {"ts": _now(), "event": event, "request_id": request_id}
    for k, v in fields.items():
        record[k] = v if isinstance(v, (int, float, bool)) or v is None else str(v)
    line = json.dumps(record, ensure_ascii=False)
    with _LOCK:
        try:
            with open(_LOGFILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass
        # Also to stdout, so a student watching the terminal sees the trail
        # as they drive the store.
        print("AUDIT " + line, file=sys.stderr)


def tail(n=50):
    """Return the last n audit lines, for the admin service to show."""
    try:
        with open(_LOGFILE, encoding="utf-8") as f:
            return f.readlines()[-n:]
    except OSError:
        return []
