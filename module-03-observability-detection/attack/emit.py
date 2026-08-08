#!/usr/bin/env python3
"""
hwz-emit  —  generate the app-layer signal the detection chain is built to catch.

WHY THIS EXISTS
---------------
Chapter 9's API runs on your laptop and logs to stderr. Nothing in this course
has ever written a line into the cloud log group, so /hwz-lab/app is empty and
the two app-layer metric filters would have nothing to count even after you
harden. This tool is the missing link: it writes the same JSON audit lines the
API would write, straight into the log group, so the chain has an input.

It is deliberately NOT a server. Chapter 10 is about the detection chain, not
about hosting an app. Standing up compute to manufacture log lines would cost
money, add teardown risk, and teach nothing about detection. A log line is the
input to the chain; this produces log lines.

THE CONTRACT (this must match foundation/modules/detection/main.tf exactly)
--------------------------------------------------------------------------
  filter: { ($.status = 401) || ($.status = 403) }  ->  alarm at Sum >= 5 / 60s
  filter: { $.status = 429 }                        ->  alarm at Sum >= 1 / 60s

Note "$.status = 401" with no quotes. The filter matches a JSON *number*. If you
emit "status": "401" as a string it will not match, the metric stays flat, and
you will spend an hour blaming the alarm. --selftest catches exactly that.

THE ORDERING RULE THAT BITES EVERYONE
-------------------------------------
A metric filter only evaluates events ingested AFTER the filter exists. Events
you emit while blind are not counted retroactively when you harden. So you emit
twice: once blind (to prove the silence) and once wired (to prove the page).

Usage:
  python attack/emit.py --selftest              # offline, no AWS, no cost
  python attack/emit.py --dry-run               # show the lines, send nothing
  python attack/emit.py                         # emit all bursts for real

© 2026 Vigilantia Technologies INC. ™ HackWithZach.
"""

import argparse
import json
import os
import sys
import time
import uuid

LOG_GROUP = "/hwz-lab/app"
REGION = "us-east-1"

ROUTE = "/v1/complete"

# ---------------------------------------------------------------------------
# BATCH CONSTRUCTION  (pure functions over no state; no AWS in here)
# The whole point of keeping this pure is that --selftest can prove the payload
# will trip the alarms BEFORE you spend a cent or wait on an alarm period.
# ---------------------------------------------------------------------------

# Thresholds copied from the Terraform. Emit one over each so a single run is
# unambiguous -- a run that exactly equals the threshold makes an off-by-one
# argument possible, and this lab exists to remove arguments.
N_NORMAL = 8
N_UNAUTHORIZED = 6      # alarm threshold is 5 in 60s
N_COSTCAP = 2           # alarm threshold is 1 in 60s


def _line(status, detail, principal, tokens=0, cost=0.0):
    """One structured audit line, shaped like the API's own audit event."""
    return {
        "audit": True,
        "request_id": str(uuid.uuid4()),
        "route": ROUTE,
        "principal": principal,
        "status": status,          # NUMBER, not string -- see module docstring
        "detail": detail,
        "tokens": tokens,
        "cost_usd": round(cost, 6),
    }


def build_batch(burst="all"):
    """Return the list of audit events for the requested burst."""
    ev = []

    if burst in ("all", "normal"):
        for i in range(N_NORMAL):
            ev.append(_line(200, "ok", "user_carol", tokens=40 + i,
                            cost=(40 + i) * 0.00002))

    if burst in ("all", "unauthorized"):
        # Credential stuffing / token abuse: the same principal hammering the
        # route with bad or mis-scoped tokens. Mixed 401 and 403 on purpose --
        # the filter is an OR and students should see both arms fire it.
        for i in range(N_UNAUTHORIZED):
            if i % 3 == 2:
                ev.append(_line(403, "Token audience mismatch", "attacker_mallory"))
            else:
                ev.append(_line(401, "Invalid token", "attacker_mallory"))

    if burst in ("all", "costcap"):
        # LLM10 unbounded consumption: the caller is pushing the rate cap.
        for _ in range(N_COSTCAP):
            ev.append(_line(429, "Rate cap exceeded", "attacker_mallory"))

    return ev


# ---------------------------------------------------------------------------
# THE FILTER PREDICATES, RE-IMPLEMENTED
# These are Python copies of the two CloudWatch filter patterns. Keeping them
# here lets --selftest judge the payload with the same rule AWS will use.
# ---------------------------------------------------------------------------
def matches_unauthorized(e):
    """{ ($.status = 401) || ($.status = 403) }"""
    s = e.get("status")
    return isinstance(s, int) and not isinstance(s, bool) and s in (401, 403)


def matches_costcap(e):
    """{ $.status = 429 }"""
    s = e.get("status")
    return isinstance(s, int) and not isinstance(s, bool) and s == 429


# ---------------------------------------------------------------------------
# LAB CONSOLE MAP
# Ties this CLI run to its card in the HWZ Lab Console. This tool is a signal
# generator, not a scanner, so its state comes from whether the detection layer
# actually exists -- one cheap read. Same command, run twice, two stories:
#   blind  -> the red   card, verdict "BLIND"   (it happened, nobody was paged)
#   wired  -> the green card, verdict "WIRED"   (it happened, the alarm fires)
# ---------------------------------------------------------------------------
CONSOLE_CARD = "Observability & Detection"      # Chapter 10  ·  Pillar: Cloud
CONSOLE_WEAK = "BLIND"
CONSOLE_HARD = "WIRED"


def console_map(wired, unauth, costcap):
    rule = "  " + "─" * 62
    print()
    print(rule)
    print("  LAB CONSOLE MAP  —  what you just saw, on the chart")
    print(rule)
    print(f"  Card   : {CONSOLE_CARD}   (Chapter 10  ·  Pillar: Cloud)")
    if wired:
        print(f'  State  : HARDENED  · green   Console verdict: "{CONSOLE_HARD}"')
        print(f"  Match  : {unauth} unauthorized + {costcap} cost-cap event(s) emitted into a")
        print("           log group that IS being counted. Both alarms cross threshold")
        print("           inside one 60s period and publish to the alert topic.")
        print("  Next   : CloudWatch > Alarms — watch them go ALARM, then check your inbox.")
    else:
        print(f'  State  : WEAK      · red     Console verdict: "{CONSOLE_WEAK}"')
        print(f"  Match  : {unauth} unauthorized + {costcap} cost-cap event(s) are now written")
        print("           down in the log group, and NOTHING counted them. The evidence")
        print("           exists and no one was paged — which is what the red card shows.")
        print("  Next   : read the lines in CloudWatch Logs. They were always there.")
    print(f'  Chart  : flip the "{CONSOLE_CARD}" card in the Lab Console for the same result.')
    print(rule)


# ---------------------------------------------------------------------------
# SELFTEST  (offline: no AWS, no network, no cost)
# ---------------------------------------------------------------------------
def selftest():
    ok = True
    ev = build_batch("all")

    # 1. Every line must be JSON-serialisable. CloudWatch takes a string; if
    #    json.dumps raises here it would raise at send time too.
    try:
        for e in ev:
            json.loads(json.dumps(e))
    except Exception as exc:                                  # pragma: no cover
        print(f"  ! events are not JSON-serialisable: {exc}")
        ok = False

    # 2. status must be a NUMBER on every line. This is the failure that costs
    #    people an hour, so it gets its own assertion.
    bad = [e for e in ev if not isinstance(e.get("status"), int)
           or isinstance(e.get("status"), bool)]
    print(f"selftest: {len(ev)} events built, {len(bad)} with a non-numeric status "
          f"(expected 0)")
    if bad:
        print("  ! a string status will not match { $.status = 401 } and the "
              "metric will stay flat")
        ok = False

    # 3. The payload must actually cross both alarm thresholds.
    u = sum(1 for e in ev if matches_unauthorized(e))
    c = sum(1 for e in ev if matches_costcap(e))
    print(f"selftest: unauthorized filter matches {u} event(s) (alarm needs >= 5)")
    print(f"selftest: cost-cap     filter matches {c} event(s) (alarm needs >= 1)")
    if u < 5:
        print("  ! unauthorized burst will not trip its alarm"); ok = False
    if c < 1:
        print("  ! cost-cap burst will not trip its alarm"); ok = False

    # 4. The predicates must not be trivially true -- a filter that matches
    #    everything is as useless as one that matches nothing.
    normal = build_batch("normal")
    leak = [e for e in normal if matches_unauthorized(e) or matches_costcap(e)]
    print(f"selftest: {len(leak)} clean 200-response event(s) wrongly matched "
          f"(expected 0)")
    if leak:
        print("  ! the filters would count normal traffic as an attack"); ok = False

    print("selftest:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# LIVE EMIT  (boto3; only imported when actually writing to an account)
# ---------------------------------------------------------------------------
def detection_present(logs, log_group, project):
    """One cheap read: does a metric filter for this project exist on this log
    group? Decides whether the banner tells the blind story or the wired one."""
    try:
        resp = logs.describe_metric_filters(logGroupName=log_group)
        return any(project in mf.get("filterName", "")
                   for mf in resp.get("metricFilters", []))
    except Exception:
        return False


def emit(events, log_group, region, project):
    import boto3
    from botocore.exceptions import ClientError

    logs = boto3.client("logs", region_name=region)

    stream = f"hwz-emit-{time.strftime('%Y%m%d-%H%M%S')}"
    try:
        logs.create_log_stream(logGroupName=log_group, logStreamName=stream)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceAlreadyExistsException":
            raise

    # PutLogEvents requires timestamps in ascending order within the batch, and
    # every event must land inside ONE 60-second window or the Sum statistic
    # splits across two periods and neither half crosses the threshold.
    now = int(time.time() * 1000)
    payload = [{"timestamp": now + i, "message": json.dumps(e)}
               for i, e in enumerate(events)]

    logs.put_log_events(logGroupName=log_group, logStreamName=stream,
                        logEvents=payload)

    print(f"emitted {len(payload)} event(s) -> {log_group}  (stream {stream})")
    return logs, stream


def main():
    ap = argparse.ArgumentParser(
        description="hwz-emit: write the app-layer audit lines the detection "
                    "chain is built to catch")
    ap.add_argument("--log-group", default=os.environ.get("HWZ_LOG_GROUP", LOG_GROUP))
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", REGION))
    ap.add_argument("--project", default="hwz")
    ap.add_argument("--burst", default="all",
                    choices=["all", "normal", "unauthorized", "costcap"])
    ap.add_argument("--dry-run", action="store_true",
                    help="Print the lines that would be sent; touch nothing")
    ap.add_argument("--selftest", action="store_true",
                    help="Judge the payload offline against the filter patterns")
    a = ap.parse_args()

    if a.selftest:
        sys.exit(selftest())

    events = build_batch(a.burst)
    unauth = sum(1 for e in events if matches_unauthorized(e))
    costcap = sum(1 for e in events if matches_costcap(e))

    if a.dry_run:
        for e in events:
            print(json.dumps(e))
        print(f"\ndry-run: {len(events)} event(s), {unauth} unauthorized, "
              f"{costcap} cost-cap. Nothing was sent.")
        sys.exit(0)

    logs, _ = emit(events, a.log_group, a.region, a.project)
    console_map(detection_present(logs, a.log_group, a.project), unauth, costcap)
    sys.exit(0)


if __name__ == "__main__":
    main()
