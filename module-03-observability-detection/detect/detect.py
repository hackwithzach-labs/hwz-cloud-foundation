#!/usr/bin/env python3
"""
hwz-detect :: the secure script that proves your account is flying blind.

Module 1's scanner (hwz-scan) answers "is the door locked?" This one answers a
different question: "if someone walks through it, will you ever know?" Posture
and detection are two different jobs. A hardened foundation with no detection is
a house with good locks and no alarm: safe until it isn't, and silent when it
isn't.

Two detection surfaces, because that is what the foundation actually gives you:

  APP LAYER   CloudWatch metric filters + alarms on the app log group. Your API
              (Module 2) writes a structured line for every request, so 401/403
              floods and 429 cost-cap rejections are visible right there.

  CONTROL PLANE   EventBridge rules on CloudTrail management events. The foundation
              trail delivers to S3 (for Athena history), not to CloudWatch Logs,
              so real-time control-plane detection rides EventBridge, not metric
              filters: someone stopping the trail, opening a security group to the
              world, or using the root account fires a rule the instant it happens.

  BEHAVIORAL / POSTURE   GuardDuty (managed behavioral detection), AWS Config
              (posture + drift history), Security Hub (one prioritized view).

How the course uses it:
  1. Deploy the detection layer WEAK (blind) on top of the hardened foundation.
  2. Run this. It FAILS loudly across all three surfaces. You are blind.
  3. Attack the stack (Module 2's harness) and review the logs. The evidence is
     in CloudTrail and the app log, but nothing told you.
  4. Harden the detection layer (one profile flip). Everything comes up.
  5. Run this again: PASS. Re-run the attack: an alarm fires, an EventBridge rule
     publishes, a finding lands in Security Hub. Now you can see.

Same split as hwz-scan on purpose: collect_live() turns the account into a plain
snapshot dict, run_checks() judges it. So the logic is testable with no AWS at
all: `python detect.py --selftest` runs the checks against a known-blind and a
known-wired fixture and proves them.

(C) 2026 Vigilantia Technologies INC. All rights reserved.
"""
import argparse, json, sys, os

SEV = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

# App-layer signals, watched with CloudWatch metric filters on the app log group.
REQUIRED_METRIC_FILTERS = {
    "unauthorized-access": ("HIGH",
        "No metric filter for repeated 401/403 in the app log. Credential stuffing "
        "and token abuse pass unseen."),
    "cost-cap-breach": ("HIGH",
        "No metric filter for 429 cost-cap rejections. The unbounded-consumption "
        "attack (LLM10) triggers no alarm."),
}

# Control-plane signals, watched with EventBridge rules on CloudTrail events.
REQUIRED_EVENTBRIDGE_RULES = {
    "cloudtrail-tamper": ("HIGH",
        "No EventBridge rule for StopLogging / DeleteTrail / UpdateTrail. An "
        "attacker blinding your audit trail is itself unaudited."),
    "sg-open-to-world": ("MEDIUM",
        "No EventBridge rule for AuthorizeSecurityGroupIngress to 0.0.0.0/0. "
        "Someone re-opening the door leaves no alert."),
    "root-account-use": ("MEDIUM",
        "No EventBridge rule for root account usage. Root should never be used; "
        "when it is, you want to know inside a minute."),
}


# ---------------------------------------------------------------------------
# CHECKS  (pure functions over a snapshot dict; no AWS in here)
# ---------------------------------------------------------------------------
def check_metric_filters(snap):
    """Is each required signal being counted anywhere?

    Matching is a SUBSTRING, not endswith, and that is not cosmetic. Filters are
    now created per log group, so a name looks like

        hwz-lab-unauthorized-access-aws-lambda-hwz-lab-emitter

    -- the group suffix lands after the signal name. An endswith match sees six
    correctly deployed filters and reports that none exist. This check answers
    "is this signal counted somewhere"; check_filter_coverage answers the harder
    question of whether it is counted on every group that receives events.
    """
    f = []
    names = [m.get("name", "") for m in snap.get("metric_filters", [])]
    for key, (sev, msg) in REQUIRED_METRIC_FILTERS.items():
        if not any(key in n for n in names):
            f.append((sev, "cw-filter", key, msg))
    return f


def check_alarms(snap):
    """Every app-layer metric filter needs an alarm, and every alarm needs an
    action (the SNS topic). A metric with no alarm is a number nobody reads."""
    f = []
    alarms = {a["metric"]: a for a in snap.get("alarms", [])}
    for mf in snap.get("metric_filters", []):
        al = alarms.get(mf.get("metric_name"))
        if not al:
            f.append(("MEDIUM", "cw-alarm", mf["name"],
                      "Metric filter exists but no alarm watches it. The signal is "
                      "recorded and ignored."))
        elif not al.get("alarm_actions"):
            f.append(("MEDIUM", "cw-alarm", mf["name"],
                      "Alarm exists but has no action. It turns red on a dashboard "
                      "nobody is looking at and pages no one."))
    return f


def check_eventbridge_rules(snap):
    """Control-plane rules must exist, be ENABLED, and target the alert topic."""
    f = []
    rules = snap.get("eventbridge_rules", [])
    for key, (sev, msg) in REQUIRED_EVENTBRIDGE_RULES.items():
        r = next((x for x in rules if x.get("name", "") == key
                  or x.get("name", "").endswith(key)), None)
        if not r:
            f.append((sev, "eventbridge", key, msg))
        elif r.get("state") != "ENABLED":
            f.append((sev, "eventbridge", key,
                      "Rule exists but is DISABLED. A paused detection is no detection."))
        elif not r.get("targets_sns"):
            f.append(("MEDIUM", "eventbridge", key,
                      "Rule matches but has no SNS target. It notices and tells no one."))
    return f


def check_alert_path(snap):
    """SNS topic with at least one CONFIRMED subscription. Alarms, EventBridge
    rules, and GuardDuty all publish here; with no confirmed subscriber they fire
    into the void."""
    f = []
    topic = snap.get("alert_topic")
    if not topic or not topic.get("exists"):
        f.append(("HIGH", "sns", "-",
                  "No alert SNS topic. Alarms, rules, and findings have nowhere to go."))
        return f
    if topic.get("confirmed_subscriptions", 0) < 1:
        f.append(("HIGH", "sns", topic.get("name", "-"),
                  "Alert topic has no confirmed subscription. The student has not "
                  "confirmed the email AWS sent, so every alert is published to silence."))
    return f


def check_guardduty(snap):
    f = []
    if not snap.get("guardduty", {}).get("enabled"):
        f.append(("HIGH", "guardduty", "-",
                  "GuardDuty is off. No behavioral detection on CloudTrail, DNS, or "
                  "VPC flow logs. The managed baseline every account should have."))
    return f


def check_config(snap):
    f = []
    cfg = snap.get("config", {})
    if not cfg.get("recording"):
        f.append(("MEDIUM", "config", "-",
                  "AWS Config is not recording. No posture history and no drift "
                  "detection: you cannot prove what changed or when."))
    elif cfg.get("rules", 0) < 1:
        f.append(("LOW", "config", "-",
                  "Config records but has no rules. Recording without evaluation is "
                  "storage, not compliance."))
    return f


def check_security_hub(snap):
    f = []
    if not snap.get("security_hub", {}).get("enabled"):
        f.append(("MEDIUM", "sec-hub", "-",
                  "Security Hub is off. GuardDuty and Config findings stay in "
                  "separate consoles instead of one prioritized view."))
    return f


def check_cloudtrail_queryable(snap):
    """The chapter teaches Athena-over-CloudTrail for cheap historical hunting.
    That only works if the trail is delivering to S3 (the hardened foundation
    ensures this). Surfaced as a low reminder, not a blocker."""
    f = []
    if not snap.get("cloudtrail", {}).get("delivering_to_s3"):
        f.append(("LOW", "athena", "-",
                  "CloudTrail is not delivering to S3, so Athena historical queries "
                  "have no data. Detection can watch the present but cannot hunt the past."))
    return f


# ---------------------------------------------------------------------------
# LOG DELIVERY  —  the half of the chain the first version of this scanner
# never checked.
#
# Everything above judges what happens AFTER a log event exists. These four
# judge whether an event exists at all. Detection is arithmetic on a stream;
# with no stream, the most carefully configured filter in the account counts
# zero forever and reports nothing wrong while it does it.
#
# AWS answers "how does output become a log event" three different ways, and
# the failure mode is different in each, so each gets its own check.
# ---------------------------------------------------------------------------
def check_lambda_delivery(snap):
    """Lambda always delivers. What it does badly is CHOOSE."""
    f = []
    for fn in snap.get("producers", {}).get("lambda", []):
        name = fn.get("name", "?")
        if not fn.get("group_declared"):
            f.append(("MEDIUM", "log-delivery", name,
                      "Lambda log group was never declared in code, so AWS created it "
                      "with retention 'Never expire' and no KMS. You are paying to "
                      "store output forever and you did not decide to."))
            continue
        if not fn.get("retention_days"):
            f.append(("MEDIUM", "log-delivery", name,
                      "Lambda log group has no retention. Logs accumulate until "
                      "someone notices the bill."))
        if not fn.get("kms"):
            f.append(("LOW", "log-delivery", name,
                      "Lambda log group is not encrypted with a customer-managed key."))
    return f


def check_container_delivery(snap):
    """A task with no log driver is a perfectly healthy task with no evidence."""
    f = []
    for c in snap.get("producers", {}).get("containers", []):
        label = f"{c.get('family', '?')}/{c.get('container', '?')}"
        if not c.get("log_driver"):
            f.append(("HIGH", "log-delivery", label,
                      "Container has no logConfiguration. Its stdout goes to the "
                      "container runtime and dies with the task. The task still runs, "
                      "still exits zero, still reports healthy — nothing turns red."))
    return f


def check_ec2_delivery(snap):
    """Three things must all be true on EC2, and the box reports none of them."""
    f = []
    for i in snap.get("producers", {}).get("ec2", []):
        iid = i.get("id", "?")
        if not i.get("can_put_logs"):
            f.append(("HIGH", "log-delivery", iid,
                      "Instance role cannot call logs:PutLogEvents. Whatever the "
                      "application writes stays on a disk that is deleted with the "
                      "instance."))
        elif not i.get("streams_seen"):
            f.append(("HIGH", "log-delivery", iid,
                      "Instance has permission to ship but no log stream has appeared. "
                      "The CloudWatch agent is not installed, not running, or not "
                      "configured for this file. Nothing errors; nothing arrives."))
    return f


def check_filter_coverage(snap):
    """THE one that matters most.

    A metric filter is scoped to exactly ONE log group. It does not follow your
    application and it does not search the account. Attach your filters to the
    app log group while a Lambda delivers to /aws/lambda/<fn> and that Lambda is
    invisible — filters present, alarms present, dashboards green, nothing
    counted. This check compares the groups that RECEIVE logs against the groups
    that are WATCHED, and reports the difference.
    """
    f = []
    delivering = set(snap.get("delivering_log_groups", []))
    if not delivering:
        return f
    # A filter recorded without a log group predates this check; assume it sits
    # on the app group rather than silently crediting it to everything.
    watched = {mf.get("log_group") or snap.get("app_log_group", "/hwz-lab/app")
               for mf in snap.get("metric_filters", [])}
    for group in sorted(delivering - watched):
        f.append(("HIGH", "filter-coverage", group,
                  "This log group receives events and has no metric filter on it. "
                  "The producer writing here is invisible to detection no matter how "
                  "good the filters on your other groups are."))
    return f


ALL_CHECKS = [check_metric_filters, check_alarms, check_eventbridge_rules,
              check_alert_path, check_guardduty, check_config,
              check_security_hub, check_cloudtrail_queryable,
              check_lambda_delivery, check_container_delivery,
              check_ec2_delivery, check_filter_coverage]


def run_checks(snap):
    findings = []
    for c in ALL_CHECKS:
        findings.extend(c(snap))
    findings.sort(key=lambda x: -SEV[x[0]])
    return findings


# ---------------------------------------------------------------------------
# LIVE COLLECTION  (boto3; only imported when actually reading an account)
# ---------------------------------------------------------------------------
def collect_live(project, region):
    import boto3
    prefix = project
    snap = {"metric_filters": [], "alarms": [], "eventbridge_rules": [],
            "alert_topic": {}, "guardduty": {}, "config": {},
            "security_hub": {}, "cloudtrail": {},
            "app_log_group": f"/{prefix}-lab/app",
            "producers": {"lambda": [], "containers": [], "ec2": []},
            "delivering_log_groups": []}

    logs = boto3.client("logs", region_name=region)
    for page in logs.get_paginator("describe_metric_filters").paginate():
        for mf in page.get("metricFilters", []):
            name = mf.get("filterName", "")
            if prefix not in name:
                continue
            xf = (mf.get("metricTransformations") or [{}])[0]
            snap["metric_filters"].append({
                "name": name,
                "metric_name": xf.get("metricName"),
                # WHICH group this filter watches. A filter is scoped to exactly
                # one; without recording that, coverage cannot be judged.
                "log_group": mf.get("logGroupName"),
            })

    cw = boto3.client("cloudwatch", region_name=region)
    for a in cw.describe_alarms().get("MetricAlarms", []):
        if prefix not in a.get("AlarmName", ""):
            continue
        snap["alarms"].append({"metric": a.get("MetricName"),
                               "alarm_actions": a.get("AlarmActions", [])})

    ev = boto3.client("events", region_name=region)
    for r in ev.list_rules().get("Rules", []):
        name = r.get("Name", "")
        if prefix not in name:
            continue
        targets = ev.list_targets_by_rule(Rule=name).get("Targets", [])
        snap["eventbridge_rules"].append({
            "name": name,
            "state": r.get("State"),
            "targets_sns": any(":sns:" in t.get("Arn", "") for t in targets),
        })

    sns = boto3.client("sns", region_name=region)
    topic_arn = next((t["TopicArn"] for t in sns.list_topics().get("Topics", [])
                      if prefix in t["TopicArn"] and "alert" in t["TopicArn"].lower()), None)
    if topic_arn:
        subs = sns.list_subscriptions_by_topic(TopicArn=topic_arn).get("Subscriptions", [])
        confirmed = sum(1 for s in subs if s.get("SubscriptionArn", "").startswith("arn:"))
        snap["alert_topic"] = {"exists": True, "name": topic_arn.split(":")[-1],
                               "confirmed_subscriptions": confirmed}
    else:
        snap["alert_topic"] = {"exists": False}

    gd = boto3.client("guardduty", region_name=region)
    snap["guardduty"] = {"enabled": any(
        gd.get_detector(DetectorId=d).get("Status") == "ENABLED"
        for d in gd.list_detectors().get("DetectorIds", []))}

    cfg = boto3.client("config", region_name=region)
    recording = False
    try:
        recording = any(r.get("recording") for r in
                        cfg.describe_configuration_recorder_status()
                        .get("ConfigurationRecordersStatus", []))
    except Exception:
        pass
    rules = 0
    try:
        rules = len(cfg.describe_config_rules().get("ConfigRules", []))
    except Exception:
        pass
    snap["config"] = {"recording": recording, "rules": rules}

    sh = boto3.client("securityhub", region_name=region)
    try:
        sh.describe_hub(); snap["security_hub"] = {"enabled": True}
    except Exception:
        snap["security_hub"] = {"enabled": False}

    ct = boto3.client("cloudtrail", region_name=region)
    snap["cloudtrail"] = {"delivering_to_s3": any(
        project in t.get("Name", "") and t.get("S3BucketName")
        for t in ct.describe_trails().get("trailList", []))}

    # -----------------------------------------------------------------------
    # PRODUCERS: who actually writes into a log group.
    #
    # Every block below is individually wrapped. A missing permission on one
    # service must degrade that one check, never kill the whole scan — a
    # security tool that dies halfway and prints nothing is worse than one that
    # reports partial coverage honestly.
    # -----------------------------------------------------------------------
    prod = {"lambda": [], "containers": [], "ec2": []}
    delivering = set()

    # Group metadata in one pass: retention and KMS for every project group.
    groups = {}
    try:
        for page in logs.get_paginator("describe_log_groups").paginate():
            for g in page.get("logGroups", []):
                groups[g["logGroupName"]] = {
                    "retention_days": g.get("retentionInDays"),
                    "kms": bool(g.get("kmsKeyId")),
                }
    except Exception:
        pass

    try:
        lam = boto3.client("lambda", region_name=region)
        for page in lam.get_paginator("list_functions").paginate():
            for fn in page.get("Functions", []):
                if prefix not in fn.get("FunctionName", ""):
                    continue
                lg = f"/aws/lambda/{fn['FunctionName']}"
                meta = groups.get(lg)
                prod["lambda"].append({
                    "name": fn["FunctionName"],
                    "log_group": lg,
                    # Declared in code, or created by the service on first invoke?
                    # We cannot see Terraform from here, but a group with neither
                    # retention nor a key is the service default in all but name.
                    "group_declared": bool(meta and (meta["retention_days"] or meta["kms"])),
                    "retention_days": (meta or {}).get("retention_days"),
                    "kms": (meta or {}).get("kms", False),
                })
                if lg in groups:
                    delivering.add(lg)
    except Exception:
        pass

    try:
        ecs = boto3.client("ecs", region_name=region)
        for arn in ecs.list_task_definitions(status="ACTIVE").get("taskDefinitionArns", []):
            if prefix not in arn:
                continue
            td = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
            for c in td.get("containerDefinitions", []):
                lc = c.get("logConfiguration") or {}
                lg = (lc.get("options") or {}).get("awslogs-group")
                prod["containers"].append({
                    "family": td.get("family"),
                    "container": c.get("name"),
                    "log_driver": lc.get("logDriver"),
                    "log_group": lg,
                })
                if lg:
                    delivering.add(lg)
    except Exception:
        pass

    try:
        ec2 = boto3.client("ec2", region_name=region)
        iam = boto3.client("iam")
        app_group = snap.get("app_log_group", f"/{prefix}/app")
        for res in ec2.describe_instances(
                Filters=[{"Name": "tag:Project", "Values": [project]},
                         {"Name": "instance-state-name", "Values": ["running"]}]
        ).get("Reservations", []):
            for inst in res.get("Instances", []):
                iid = inst["InstanceId"]
                can_put = False
                prof = (inst.get("IamInstanceProfile") or {}).get("Arn", "")
                if prof:
                    try:
                        pname = prof.rsplit("/", 1)[-1]
                        roles = iam.get_instance_profile(
                            InstanceProfileName=pname)["InstanceProfile"]["Roles"]
                        for r in roles:
                            for pol in iam.list_role_policies(
                                    RoleName=r["RoleName"]).get("PolicyNames", []):
                                doc = iam.get_role_policy(
                                    RoleName=r["RoleName"], PolicyName=pol)["PolicyDocument"]
                                if "logs:PutLogEvents" in json.dumps(doc):
                                    can_put = True
                    except Exception:
                        pass
                # Has anything actually arrived from this instance?
                seen = False
                try:
                    seen = bool(logs.describe_log_streams(
                        logGroupName=app_group, logStreamNamePrefix=iid,
                        limit=1).get("logStreams"))
                except Exception:
                    pass
                prod["ec2"].append({"id": iid, "can_put_logs": can_put,
                                    "streams_seen": seen})
                if seen:
                    delivering.add(app_group)
    except Exception:
        pass

    snap["producers"] = prod
    snap["delivering_log_groups"] = sorted(delivering)
    return snap


# ---------------------------------------------------------------------------
# REPORT + CLI
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# LAB CONSOLE MAP  (added) — ties this CLI run to its card in the HWZ Lab
# Console, so terminal output and the dashboard are provably the same story.
#   findings (rc=1) -> the red card;   clean (rc=0) -> the green card.
# ---------------------------------------------------------------------------
_CONSOLE_CARD = 'Observability & Detection'
_CONSOLE_META = 'Chapter 10 · Pillar: Cloud'
_CONSOLE_WEAK = 'BLIND'
_CONSOLE_HARD = 'WIRED'
_CONSOLE_UNIT = 'gap(s)'
_CONSOLE_WLINE = 'the SOC is blind — it happens and no one is paged'
_CONSOLE_HLINE = 'every surface alarms'


def console_map(rc, n):
    rule = "  " + "─" * 62
    print()
    print(rule)
    print("  LAB CONSOLE MAP  —  what you just saw, on the chart")
    print(rule)
    print(f"  Card   : {_CONSOLE_CARD}   ({_CONSOLE_META})")
    if rc == 0:
        print(f'  State  : HARDENED  · green   Console verdict: "{_CONSOLE_HARD}"')
        print(f"  Match  : {_CONSOLE_HLINE} — exactly what the green card shows.")
    else:
        print(f'  State  : WEAK      · red     Console verdict: "{_CONSOLE_WEAK}"')
        print(f"  Match  : {n} {_CONSOLE_UNIT} — {_CONSOLE_WLINE},")
        print("           which is what the red card shows.")
    print(f'  Chart  : flip the "{_CONSOLE_CARD}" card in the Lab Console for the same result.')
    print(rule)


def report(*a, **k):
    rc = _report(*a, **k)
    try:
        n = len(a[-1])
    except Exception:
        n = rc
    console_map(rc, n)
    return rc


def _report(findings):
    if not findings:
        print("PASS. Detection is wired. If it happens, you will see it.")
        return 0
    print(f"BLIND. {len(findings)} gap(s):\n")
    for sev, svc, res, msg in findings:
        print(f"  [{sev:6}] {svc:12} {res:20} {msg}")
    highs = sum(1 for f in findings if f[0] == "HIGH")
    print(f"\n{highs} HIGH severity. Close these first, then re-run. Detection is "
          f"half the job; right now you are doing the other half in the dark.")
    return 1


def selftest():
    here = os.path.dirname(__file__)
    ok = True
    with open(os.path.join(here, "fixtures", "blind.json")) as fh:
        blind = run_checks(json.load(fh))
    with open(os.path.join(here, "fixtures", "wired.json")) as fh:
        wired = run_checks(json.load(fh))
    print(f"selftest: blind fixture -> {len(blind)} gaps (expected > 0)")
    print(f"selftest: wired fixture -> {len(wired)} gaps (expected 0)")
    if len(blind) == 0:
        print("  ! blind fixture produced no gaps, checks are broken"); ok = False
    if len(wired) != 0:
        print("  ! wired fixture produced gaps, checks are too strict:"); ok = False
        for x in wired:
            print("     ", x)
    print("selftest:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(
        description="hwz-detect: prove the account is blind, then prove it can see")
    ap.add_argument("--project", default="hwz", help="Project / name prefix to scope the read")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--snapshot", help="Judge a saved snapshot JSON instead of live AWS")
    ap.add_argument("--selftest", action="store_true", help="Run checks against fixtures, no AWS")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest())
    if a.snapshot:
        with open(a.snapshot) as fh:
            snap = json.load(fh)
    else:
        snap = collect_live(a.project, a.region)
    sys.exit(report(run_checks(snap)))


if __name__ == "__main__":
    main()
