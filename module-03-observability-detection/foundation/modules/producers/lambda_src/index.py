"""
hwz log producer :: LAMBDA

The point of this function is not what it computes. It is WHERE its output ends
up, and who decided that.

A Lambda function writes to stdout. The Lambda service captures stdout and
delivers it to a CloudWatch log group named /aws/lambda/<function-name>. You do
not install anything and you do not configure anything -- but you also do not
CHOOSE anything. If you never declare that log group in Terraform, the service
creates it for you on first invocation with retention set to "Never expire" and
no KMS key. That is how accounts end up paying to store years of debug output in
plaintext, and it is the single most common CloudWatch cost surprise.

So the hardened profile of this lab declares the group explicitly and Lambda
reuses it. Same logs, chosen retention, chosen encryption.

© 2026 Vigilantia Technologies INC. TM HackWithZach.
"""

import json
import os
import uuid

ROUTE = "/v1/complete"

# Kept identical to attack/emit.py so every producer in this lab emits the same
# shape. The metric filter matches { $.status = 401 } against a JSON NUMBER --
# quoting status here would silently break the whole chain.
N_NORMAL = 8
N_UNAUTHORIZED = 6      # alarm threshold is 5 in 60s
N_COSTCAP = 2           # alarm threshold is 1 in 60s


def line(status, detail, principal, tokens=0, cost=0.0):
    return {
        "audit": True,
        "producer": "lambda",
        "request_id": str(uuid.uuid4()),
        "route": ROUTE,
        "principal": principal,
        "status": status,
        "detail": detail,
        "tokens": tokens,
        "cost_usd": round(cost, 6),
    }


def build_batch(burst="all"):
    ev = []
    if burst in ("all", "normal"):
        for i in range(N_NORMAL):
            ev.append(line(200, "ok", "user_carol", 40 + i, (40 + i) * 0.00002))
    if burst in ("all", "unauthorized"):
        for i in range(N_UNAUTHORIZED):
            if i % 3 == 2:
                ev.append(line(403, "Token audience mismatch", "attacker_mallory"))
            else:
                ev.append(line(401, "Invalid token", "attacker_mallory"))
    if burst in ("all", "costcap"):
        for _ in range(N_COSTCAP):
            ev.append(line(429, "Rate cap exceeded", "attacker_mallory"))
    return ev


def handler(event, context):
    burst = (event or {}).get("burst", os.environ.get("HWZ_BURST", "all"))
    events = build_batch(burst)

    # One JSON object per line on stdout. That is the entire contract between
    # this function and CloudWatch Logs.
    for e in events:
        print(json.dumps(e))

    unauth = sum(1 for e in events if e["status"] in (401, 403))
    costcap = sum(1 for e in events if e["status"] == 429)

    return {
        "emitted": len(events),
        "unauthorized": unauth,
        "costcap": costcap,
        "log_group": os.environ.get("AWS_LAMBDA_LOG_GROUP_NAME", "unknown"),
    }
