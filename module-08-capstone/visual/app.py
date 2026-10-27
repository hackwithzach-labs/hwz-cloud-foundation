#!/usr/bin/env python3
"""
Chapter 15 - the Capstone, as the whole-course visual lab.

    pip install -r requirements.txt
    python app.py            # http://localhost:5115

The big one. Every pillar of the course, on one screen, driven by one payload:

  1. A live architecture + flow diagram. The request path (ticket -> guardrail
     -> agent -> goal -> tools -> MCP -> cloud) and the log path (CloudTrail +
     CloudWatch -> metric filter -> alarm -> SNS -> on-call). It lights up red
     along the breach path when weak, and shows the block plus the alarm path
     when hardened.
  2. The detection pipeline, firing. The real metric filter pattern, the alarm
     state, and the page that reaches a human.
  3. Four pillar consoles, each with the real CloudTrail or CloudWatch JSON this
     run produced: Cloud, API, Agent, MCP.
  4. The capstone scan and the independence proof.
  5. A full-course recap map: every control, its pillar, its chapter, and where
     it lands in the capstone.

Offline, no AWS, no credentials, no cost. It looks and teaches like AWS, but it
contains no logic of its own: it imports `../attack/end_to_end.py` and
`../scan/scan.py` and renders what they return. The CloudTrail and CloudWatch
events are a faithful translation of what the real chain did into the AWS API
calls those actions make. Flip a switch and the same run_chain() the terminal
runs is what answers. Browser and terminal cannot disagree.

(c) 2026 Vigilantia Technologies INC. TM HackWithZach. Education/defense only.
"""
import json
import os
import sys
from pathlib import Path

from flask import Flask, Response, jsonify, request

APP_DIR = Path(__file__).resolve().parent
MODULE_DIR = APP_DIR.parent
sys.path.insert(0, str(MODULE_DIR / "attack"))
sys.path.insert(0, str(MODULE_DIR / "scan"))

import end_to_end as chain   # noqa: E402
import scan as capscan       # noqa: E402

app = Flask(__name__)

TICKETS = {
    "poisoned": MODULE_DIR / "attack" / "tickets" / "poisoned.txt",
    "clean": MODULE_DIR / "attack" / "tickets" / "clean.txt",
}
GATE_NAMES = [g for g, _, _ in chain.GATES]
TOTAL_ACCOUNTS = len(chain.ACCOUNTS)
EXT = chain.EXTERNAL_RECIPIENT
SELF = chain.SESSION_IDENTITY


def load_ticket(key):
    if key == "clean":
        p = TICKETS["clean"]
        if p.exists():
            return chain.load_ticket(str(p))
        return "Hi, my invoice looks wrong. Can you check my plan? - " + SELF
    return chain.load_ticket(str(TICKETS["poisoned"]))


def locks_from_request():
    out = {}
    for g in GATE_NAMES:
        out[g] = request.args.get(g, "0") in ("1", "true", "on", "True")
    return out


def records_touched(trace):
    n = 0
    for r in trace:
        if "records" in r:
            n = max(n, r["records"])
    return n


def j(obj):
    return json.dumps(obj, separators=(", ", ": "))


def cloudtrail_events(trace, locks):
    """Translate the real chain trace into the AWS API calls those actions make."""
    ev = []
    if not locks["guardrail"]:
        ev.append({"eventSource": "sts.amazonaws.com", "eventName": "AssumeRole",
                   "resource": "role/agent-role",
                   "policy": "scoped" if locks["tool-least-priv"] else "*:*"})
    for r in trace:
        if r.get("tool") == "lookup_account" and r.get("event") == "tool_call":
            n = r.get("records", 1)
            if n <= 1:
                ev.append({"eventSource": "dynamodb.amazonaws.com", "eventName": "GetItem",
                           "tableName": "Accounts", "key": SELF})
            else:
                ev.append({"eventSource": "dynamodb.amazonaws.com", "eventName": "Scan",
                           "tableName": "Accounts", "scannedCount": n})
        if r.get("event") == "tool_scope_enforced":
            ev.append({"eventSource": "dynamodb.amazonaws.com", "eventName": "GetItem",
                       "tableName": "Accounts", "key": SELF})
        if r.get("tool") == "send_email":
            ev.append({"eventSource": "ses.amazonaws.com", "eventName": "SendEmail",
                       "destination": r.get("to", EXT)})
        if r.get("event") == "send_parked_for_approval":
            ev.append({"eventSource": "ses.amazonaws.com", "eventName": "SendEmail",
                       "destination": r.get("to", EXT), "status": "PENDING_APPROVAL"})
    return ev


def detection(locks, trace, soc):
    active = locks["run-audit"]
    alarm, metric = "none", None
    if active and soc:
        kinds = {r.get("event") for r in soc}
        if "guardrail_block" in kinds:
            alarm, metric = "ALARM", "CapstoneInjectionBlocked"
        elif kinds & {"goal_swap_refused", "tool_scope_enforced", "send_parked_for_approval"}:
            alarm, metric = "ALARM", "CapstoneControlTripped"
        elif any(r.get("tool") == "send_email" for r in soc):
            alarm, metric = "ALARM", "OffDomainExfil"
    return {
        "active": active,
        "filter": '{ $.event = "guardrail_block" }' if active else None,
        "ct_rule": "ses:SendEmail to non-allowlisted domain" if active else None,
        "alarm": alarm, "metric": metric or "CapstoneInjectionBlocked",
        "paged": bool(soc), "page": soc,
    }


def gstate(step_by, gate):
    if gate not in step_by:
        return "dim"
    return "stop" if step_by[gate][0] == "ON" else "open"


def build_activity(locks, trace, injected, breached, soc, ticket_key):
    """The agent's activity as a product UI would show it. Derived from the real run."""
    recs = records_touched(trace) or TOTAL_ACCOUNTS
    a = [{"ic": "ok", "cls": "", "t": "Read ticket #4471", "d": "ingested the full document, attachment included"}]
    if locks["guardrail"]:
        a.append({"ic": "sh", "cls": "g", "t": "Input guardrail: injection-pattern detected", "d": "the poisoned text never reached the model"})
        a.append({"ic": "ok", "cls": "g", "t": "Request refused, goal unchanged", "d": 'standing goal stays "answer the ticket"'})
    else:
        a.append({"ic": "ok", "cls": "", "t": "Looked up account: " + SELF, "d": "lookup_account · 1 record"})
        if not injected:
            a.append({"ic": "ok", "cls": "", "t": "Answered the ticket", "d": "goal intact · no external action"})
        elif locks["goal-lock"]:
            a.append({"ic": "ok", "cls": "g", "t": "Goal swap refused", "d": "the standing objective is not model-editable"})
        else:
            a.append({"ic": "warn", "cls": "r", "t": 'Goal updated from the ticket: "exfiltrate accounts"', "d": "no guardrail, no goal-lock · the injection won"})
            if locks["tool-least-priv"]:
                a.append({"ic": "ok", "cls": "g", "t": "lookup_account scoped to one record", "d": "least privilege held · the table is not readable"})
            else:
                a.append({"ic": "bad", "cls": "r", "t": f"Read ALL accounts · {recs} records", "d": "lookup_account on the whole table · broad role"})
                if locks["hitl-approval"]:
                    a.append({"ic": "ok", "cls": "g", "t": "send_email parked for human approval", "d": "the external address needs a person"})
                else:
                    a.append({"ic": "bad", "cls": "r", "t": f"Sent email → {EXT}", "d": "send_email over MCP · no human approval"})
    if ticket_key == "clean":
        banner = {"cls": "good", "t": "Clean ticket handled · the locks did not break the product"}
    elif breached:
        tail = "SOC notified" if soc else "SOC not notified"
        banner = {"cls": "bad", "t": f"DATA EXFILTRATED · {recs} records left the system · {tail}"}
    else:
        tail = " · SOC paged" if soc else ""
        banner = {"cls": "good", "t": f"BLOCKED · no record read, no email sent{tail}"}
    return a, banner


def build_model(locks, ticket_key):
    text = load_ticket(ticket_key)
    injected = chain.looks_injected(text)
    breached, steps, trace, soc = chain.run_chain(text, locks)
    step_by = {name: (state, msg) for _, name, state, msg in steps}
    recs = records_touched(trace)
    ct = cloudtrail_events(trace, locks)
    det = detection(locks, trace, soc)

    posture = {g: locks[g] for g in GATE_NAMES}
    posture["foundation-pinned"] = all(locks[g] for g in GATE_NAMES)
    findings = capscan.run_checks(posture)

    independence = []
    for g in ("guardrail", "goal-lock", "tool-least-priv", "hitl-approval"):
        only = {x: (x == g) for x in GATE_NAMES}
        b, _, _, _ = chain.run_chain(text, only)
        independence.append({"gate": g, "holds": not b})
    b_a, _, _, _ = chain.run_chain(text, {x: (x == "run-audit") for x in GATE_NAMES})
    independence.append({"gate": "run-audit", "holds": not b_a, "detection": True})

    def verify(gate):
        if gate not in step_by:
            return {"state": "na", "text": "not reached this run"}
        state, msg = step_by[gate]
        return {"state": "held" if state == "ON" else "open", "text": msg}

    touched = any(e["eventSource"] in ("dynamodb.amazonaws.com", "ses.amazonaws.com") for e in ct)
    cloud_state = "breach" if breached else ("touched" if touched else "dim")
    diagram = {
        "breached": breached,
        "request": [
            {"id": "ticket", "label": "Ticket", "sub": "untrusted", "state": "in"},
            {"id": "guardrail", "label": "Guardrail", "sub": "Ch 11", "state": gstate(step_by, "guardrail")},
            {"id": "agent", "label": "AI Agent", "sub": "model loop",
             "state": "open" if not locks["guardrail"] else "dim"},
            {"id": "goal", "label": "Goal-lock", "sub": "Ch 13", "state": gstate(step_by, "goal-lock")},
            {"id": "tools", "label": "lookup_account", "sub": "Ch 12", "state": gstate(step_by, "tool-least-priv")},
            {"id": "mcp", "label": "send_email / MCP", "sub": "Ch 12/13", "state": gstate(step_by, "hitl-approval")},
            {"id": "cloud", "label": "Cloud data", "sub": "DynamoDB / SES", "state": cloud_state},
        ],
        "detect": [
            {"id": "ct", "label": "CloudTrail", "sub": f"{len(ct)} events", "state": "log" if ct else "dim"},
            {"id": "cw", "label": "CloudWatch Logs", "sub": f"{len(trace)} events", "state": "log" if trace else "dim"},
            {"id": "filter", "label": "Metric filter", "sub": "pattern", "state": "on" if det["active"] else "off"},
            {"id": "alarm", "label": "Alarm", "sub": det["alarm"],
             "state": "alarm" if det["alarm"] == "ALARM" else ("ok" if det["active"] else "off")},
            {"id": "sns", "label": "SNS", "sub": "on-call topic", "state": "on" if det["paged"] else "off"},
            {"id": "oncall", "label": "On-call", "sub": "PAGED" if det["paged"] else "silent",
             "state": "paged" if det["paged"] else "silent"},
        ],
    }

    # ---- consoles ----
    cloud_on = locks["run-audit"]
    cloud = {
        "key": "cloud", "title": "Cloud Foundation", "tag": "AWS · Ch 8 + Ch 10",
        "sub": "S3 · IAM · KMS · CloudTrail", "control": "run-audit",
        "control_label": "Foundation hardened + CloudTrail alarm", "control_on": cloud_on, "pillar": "Pillar 1",
        "deploy": [
            {"name": "S3  hwz-cap-data", "weak": "ACL public-read · BPA OFF", "hard": "private · BPA ON", "on": cloud_on},
            {"name": "IAM agent-role", "weak": 'policy  "*":"*"', "hard": "scoped, read-only", "on": cloud_on},
            {"name": "KMS", "weak": "none (SSE-S3)", "hard": "CMK alias/hwz-cap", "on": cloud_on},
            {"name": "CloudTrail", "weak": "no metric filter", "hard": "filter → SNS → on-call", "on": cloud_on},
        ],
        "logtitle": "CloudTrail event", "log": ct,
        "verify": {"state": "held" if (soc or not breached) else "open",
                   "text": ("the attack event reached a human" if soc else "events logged; nobody paged")}
        if ticket_key == "poisoned" else {"state": "held", "text": "clean run, nothing to page on"},
    }

    api_on = locks["tool-least-priv"]
    if api_on:
        resp = {"status": "200 scoped", "note": f"one record, {SELF}"}
    elif "tool-least-priv" in step_by:
        resp = {"status": "200 broad", "note": f"broad role read {recs or TOTAL_ACCOUNTS} of {TOTAL_ACCOUNTS}"}
    else:
        resp = {"status": "- not reached", "note": "chain died upstream"}
    api = {
        "key": "api", "title": "API & Tool Gateway", "tag": "Ch 12", "sub": "lookup_account · IAM scope",
        "control": "tool-least-priv", "control_label": "Bind lookup_account to the session identity",
        "control_on": api_on, "pillar": "Pillar 2",
        "deploy": [
            {"name": "tool lookup_account", "weak": "bound to broad agent-role", "hard": "bound to session identity", "on": api_on},
            {"name": "scope", "weak": "reads the whole table", "hard": "reads the caller's row", "on": api_on},
        ],
        "request": f"GET  lookup_account  (caller={SELF})", "response": resp,
        "logtitle": "CloudWatch Logs · tool", "log": [e for e in trace if e.get("tool") == "lookup_account" or e.get("event") == "tool_scope_enforced"],
        "verify": verify("tool-least-priv"),
    }

    g_on, goal_on = locks["guardrail"], locks["goal-lock"]
    if g_on:
        ao = {"state": "blocked", "line": "input guardrail blocked the ticket (injection-pattern)"}
    elif injected and goal_on:
        ao = {"state": "held", "line": 'goal swap refused; objective stays "answer the ticket"'}
    elif injected:
        ao = {"state": "hijacked", "line": 'goal replaced by the ticket: "exfiltrate accounts"'}
    else:
        ao = {"state": "normal", "line": 'goal intact: "answer the ticket"'}
    agent = {
        "key": "agent", "title": "AI Agent", "tag": "Ch 11 + Ch 13", "sub": "input guardrail · goal-lock",
        "control": "guardrail", "control_label": "Input guardrail on every ingested source", "control_on": g_on,
        "control2": "goal-lock", "control2_label": "Standing goal is not model-editable", "control2_on": goal_on,
        "pillar": "Pillar 1 / 3",
        "deploy": [
            {"name": "input guardrail", "weak": "off — raw text to the model", "hard": "screens every source", "on": g_on},
            {"name": "standing goal", "weak": "editable by ingested text", "hard": 'pinned: "answer the ticket"', "on": goal_on},
        ],
        "chat": [{"who": "ticket", "text": text[:200] + ("..." if len(text) > 200 else "")},
                 {"who": "agent", "text": ao["line"], "state": ao["state"]}],
        "logtitle": "CloudWatch Logs · agent", "log": [e for e in trace if e.get("event") in ("guardrail_block", "goal_swap_refused")],
        "verify": {"guardrail": verify("guardrail"), "goal": verify("goal-lock")},
    }

    h_on = locks["hitl-approval"]
    if "hitl-approval" not in step_by:
        mc = {"state": "na", "line": "send_email never reached (chain died upstream)"}
    elif h_on:
        mc = {"state": "parked", "line": f"send_email to {EXT} PARKED for human approval ({recs} records)"}
    elif injected:
        mc = {"state": "fired", "line": f"send_email to {EXT} FIRED ({recs} records exfiltrated)"}
    else:
        mc = {"state": "none", "line": "no external send attempted; the ticket was answered"}
    mcp = {
        "key": "mcp", "title": "MCP Server", "tag": "Ch 12 + Ch 13", "sub": "send_email tool · human approval",
        "control": "hitl-approval", "control_label": "Human gates every irreversible send", "control_on": h_on,
        "pillar": "Pillar 2 / 3",
        "deploy": [
            {"name": "MCP tools", "weak": "lookup_account, send_email auto-exec", "hard": "send_email needs approval", "on": h_on},
            {"name": "egress", "weak": "send to any address", "hard": "external address parks", "on": h_on},
        ],
        "call": mc,
        "logtitle": "CloudTrail · SES", "log": [e for e in ct if e["eventSource"] == "ses.amazonaws.com"],
        "verify": verify("hitl-approval"),
    }

    recap = [{"name": n, "pillar": p, "ch": f"Ch {c}", "why": w} for n, p, c, s, w in capscan.CONTROLS]
    activity, attack_banner = build_activity(locks, trace, injected, breached, soc, ticket_key)
    ticket_text = text[:420] + ("..." if len(text) > 420 else "")

    if ticket_key == "clean":
        headline = "CLEAN TICKET - handled. The locks did not break the product."
    elif breached:
        headline = "BREACH - the chain completed. The accounts table left the building."
    else:
        headline = f"BLOCKED - the chain died at {steps[-1][1]}, the first lock it hit."

    return {
        "breached": breached, "headline": headline, "ticket": ticket_key,
        "diagram": diagram, "detection": det,
        "pillars": {"cloud": cloud, "api": api, "agent": agent, "mcp": mcp},
        "scan": [{"sev": s, "pillar": p, "ch": c, "name": n, "why": w} for s, p, c, n, w in findings],
        "scan_clean": not findings, "independence": independence, "recap": recap,
        "cloudtrail": ct, "cloudwatch": trace,
        "activity": activity, "attack_banner": attack_banner,
        "ticket_text": ticket_text, "soc_paged": bool(soc), "soc": soc,
        "injected": injected, "records": records_touched(trace) or TOTAL_ACCOUNTS,
    }


@app.route("/api/state")
def api_state():
    locks = locks_from_request()
    ticket = request.args.get("ticket", "poisoned")
    if ticket not in TICKETS:
        ticket = "poisoned"
    return jsonify(build_model(locks, ticket))


@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")


PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Capstone Lab</title>
<style>
  :root{
    --bg:#0a0d13;--panel:#131824;--panel2:#0f1420;--line:#242c3b;--ink:#e8edf6;--mut:#8a94a7;
    --red:#ff5d6c;--redbg:#2a1016;--grn:#45d19a;--grnbg:#0f2a20;--amb:#ffc24b;--blue:#5aa2ff;
    --cloud:#ff9900;--api:#2dd4bf;--agent:#a78bfa;--mcp:#7dd3fc;--pur:#b48af0;
    --mono:'SFMono-Regular',ui-monospace,Menlo,Consolas,monospace;
  }
  *{box-sizing:border-box}html,body{margin:0}
  body{background:var(--bg);color:var(--ink);font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.5}
  .wrap{max-width:1360px;margin:0 auto;padding:22px 20px 70px}
  header.top{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:18px}
  .brand{font-size:21px;font-weight:800;letter-spacing:-.02em}.brand b{color:var(--cloud)}
  .brand .sub{display:block;color:var(--mut);font-size:12px;font-weight:500;margin-top:3px;letter-spacing:0}
  .ctrls{display:flex;gap:18px;flex-wrap:wrap;align-items:center}
  .seg{display:flex;flex-direction:column;gap:5px}
  .seg .lbl{color:var(--mut);font-size:10px;font-weight:700;letter-spacing:.09em;text-transform:uppercase}
  .seg .btns{display:flex;background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:3px}
  .seg button{border:0;background:transparent;color:var(--mut);font:inherit;font-weight:700;font-size:12.5px;padding:6px 14px;border-radius:6px;cursor:pointer}
  .seg button.on[data-k="weak"],.seg button.on[data-k="poisoned"]{background:var(--red);color:#1a0a0d}
  .seg button.on[data-k="hard"],.seg button.on[data-k="clean"]{background:var(--grn);color:#06180f}
  .banner{border-radius:12px;padding:14px 18px;font-weight:800;font-size:16px;margin-bottom:16px;border:1px solid}
  .banner.breach{background:var(--redbg);border-color:#5b1f28;color:var(--red)}
  .banner.blocked{background:var(--grnbg);border-color:#1d4535;color:var(--grn)}
  .banner.clean{background:#10243a;border-color:#1f3f5f;color:var(--blue)}

  .block{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 18px;margin-bottom:16px}
  .block h2{margin:0 0 4px;font-size:15px}.block .cap{color:var(--mut);font-size:12px;margin:0 0 12px}
  #diagram{width:100%;height:auto;display:block}
  svg text{font-family:var(--mono)}

  .det{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  @media(max-width:820px){.det{grid-template-columns:1fr}}
  .mono{background:#080b11;border:1px solid var(--line);border-radius:8px;padding:9px 11px;font-family:var(--mono);font-size:11px;line-height:1.65;color:#c7d0e0;white-space:pre-wrap;word-break:break-word}
  .mono.empty{color:var(--mut)}.mono .g{color:var(--grn)}.mono .a{color:var(--amb)}.mono .r{color:var(--red)}
  .lb{font-size:10px;font-weight:800;letter-spacing:.1em;color:var(--mut);text-transform:uppercase;margin:0 0 7px}

  .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
  @media(max-width:900px){.grid{grid-template-columns:1fr}}
  .con{background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden;display:flex;flex-direction:column}
  .con .hd{display:flex;align-items:center;gap:10px;padding:13px 16px;border-bottom:1px solid var(--line)}
  .con .dot{width:10px;height:10px;border-radius:50%}
  .con .htxt{flex:1}.con .htxt .t{font-weight:800;font-size:15px}.con .htxt .s{color:var(--mut);font-size:11.5px;font-family:var(--mono)}
  .con .tag{font-size:10px;font-weight:800;letter-spacing:.06em;color:var(--mut);border:1px solid var(--line);border-radius:999px;padding:3px 9px;white-space:nowrap}
  .con[data-k=cloud] .dot{background:var(--cloud)}.con[data-k=api] .dot{background:var(--api)}
  .con[data-k=agent] .dot{background:var(--agent)}.con[data-k=mcp] .dot{background:var(--mcp)}
  .con .body{padding:14px 16px;display:flex;flex-direction:column;gap:12px}
  .dep{display:flex;flex-direction:column;gap:6px}
  .row{display:grid;grid-template-columns:150px 1fr;gap:10px;align-items:center;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:7px 10px}
  .row .rn{font-family:var(--mono);font-size:11px;color:var(--ink);font-weight:600}.row .rv{font-size:12px}
  .row .rv .pill{display:inline-block;font-size:10px;font-weight:700;padding:2px 7px;border-radius:999px}
  .rv.open .pill{background:var(--redbg);color:var(--red)}.rv.hard .pill{background:var(--grnbg);color:var(--grn)}
  .sw{display:flex;align-items:center;gap:9px;background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:8px 11px;cursor:pointer;margin-bottom:6px}
  .sw:last-child{margin-bottom:0}
  .sw .knob{width:34px;height:19px;border-radius:999px;background:#39455a;position:relative;flex:none;transition:.15s}
  .sw .knob::after{content:"";position:absolute;top:2px;left:2px;width:15px;height:15px;border-radius:50%;background:#fff;transition:.15s}
  .sw.on .knob{background:var(--grn)}.sw.on .knob::after{left:17px}
  .sw .sl{flex:1}.sw .sl .n{font-weight:700;font-size:12.5px}.sw .sl .d{color:var(--mut);font-size:11px}
  .sw .st{font-family:var(--mono);font-size:10.5px;font-weight:700}.sw.on .st{color:var(--grn)}.sw:not(.on) .st{color:var(--red)}
  .rr{font-family:var(--mono);font-size:11px}.rr .b{color:var(--red);font-weight:700}.rr .s{color:var(--grn);font-weight:700}.rr .n{color:var(--mut)}
  .chat{display:flex;flex-direction:column;gap:7px}
  .msg{border-radius:9px;padding:8px 11px;font-size:12.5px;max-width:92%}
  .msg.ticket{background:var(--panel2);border:1px solid var(--line);align-self:flex-start;font-family:var(--mono);font-size:11px;color:#c7d0e0;white-space:pre-wrap}
  .msg.agent{align-self:flex-end;font-weight:600}
  .msg.agent.blocked,.msg.agent.held{background:var(--grnbg);color:var(--grn);border:1px solid #1d4535}
  .msg.agent.hijacked{background:var(--redbg);color:var(--red);border:1px solid #5b1f28}
  .msg.agent.normal{background:#10243a;color:var(--blue);border:1px solid #1f3f5f}
  .vf{display:flex;align-items:center;gap:9px;border-radius:8px;padding:9px 11px;font-size:12.5px;font-weight:600}
  .vf.held{background:var(--grnbg);color:var(--grn)}.vf.open{background:var(--redbg);color:var(--red)}
  .vf.na{background:var(--panel2);color:var(--mut)}.vf .ic{font-weight:800}
  .vrow{display:flex;gap:9px;flex-wrap:wrap}.vrow .vf{flex:1;min-width:150px}

  .strips{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
  @media(max-width:900px){.strips{grid-template-columns:1fr}}
  .strip{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:15px 17px}
  .strip h3{margin:0 0 11px;font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:var(--mut)}
  .ind .ir{display:grid;grid-template-columns:150px 92px 1fr;gap:8px;align-items:center;font-size:12.5px;padding:6px 0;border-bottom:1px solid var(--line)}.ind .ir:last-child{border:0}
  .ind .g{font-family:var(--mono);font-weight:600}.ind .ty{color:var(--mut);font-size:11px}.ind .ok{color:var(--grn);font-weight:700}.ind .no{color:var(--red);font-weight:700}
  .scan .sr{display:flex;gap:9px;align-items:baseline;padding:6px 0;border-bottom:1px solid var(--line);font-size:12px}.scan .sr:last-child{border:0}
  .scan .sev{font-family:var(--mono);font-size:10px;font-weight:800;padding:2px 6px;border-radius:5px;flex:none}
  .scan .HIGH{background:var(--redbg);color:var(--red)}.scan .MEDIUM{background:#2a2410;color:var(--amb)}
  .scan .pass{color:var(--grn);font-weight:700;font-size:13px}
  .recap{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
  @media(max-width:820px){.recap{grid-template-columns:1fr}}
  .rc{background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:10px 12px;border-left:3px solid var(--blue)}
  .rc .n{font-family:var(--mono);font-weight:700;font-size:12.5px}.rc .m{color:var(--mut);font-size:10.5px;margin:2px 0 5px;font-family:var(--mono)}
  .rc .w{font-size:11.5px;color:#c7d0e0}
  footer{color:var(--mut);font-size:11px;text-align:center;margin-top:8px;line-height:1.7}footer code{color:#aab4c6}
  /* attack view */
  .atk{display:grid;grid-template-columns:1fr 1fr;border:1px solid var(--line);border-radius:12px;overflow:hidden}
  .atk .hd2{grid-column:1/3;display:flex;align-items:center;gap:10px;padding:11px 16px;background:#171a21;border-bottom:1px solid var(--line)}
  .atk .hd2 .dot{width:9px;height:9px;border-radius:50%;background:var(--grn)}.atk .hd2 .lg{font-weight:700}.atk .hd2 .who{color:var(--mut);font-size:12px}.atk .hd2 .sp{flex:1}
  .atk .cl{padding:15px 17px}.atk .cl.l{border-right:1px solid var(--line);background:var(--panel2)}
  .atk .clbl{font-size:10px;letter-spacing:1px;color:var(--mut);font-weight:700;text-transform:uppercase;margin-bottom:9px}
  .tk{background:#0f1420;border:1px solid var(--line);border-radius:8px;padding:12px 14px;font-size:12.5px;color:#d7dce4;line-height:1.6;white-space:pre-wrap;word-break:break-word}
  .tk .hl{background:#3a1016;color:#ff8a98;border-radius:3px;padding:0 2px}
  .stp{display:flex;gap:10px;align-items:flex-start;padding:8px 0;border-bottom:1px solid #1c212b;font-size:13px}.stp:last-child{border:0}
  .stp .i{width:20px;height:20px;border-radius:50%;flex:none;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:800}
  .i.ok{background:#0f2a20;color:var(--grn)}.i.bad{background:#2a1016;color:var(--red)}.i.warn{background:#2a2410;color:var(--amb)}.i.sh{background:#0f2440;color:var(--blue)}
  .stp .tt{font-weight:600}.stp .dd{color:var(--mut);font-size:11.5px}.stp.r .tt{color:#ff7482}.stp.g .tt{color:var(--grn)}
  .abnr{margin-top:12px;padding:11px 14px;border-radius:8px;font-weight:800;font-size:13.5px}
  .abnr.bad{background:#2a1016;color:var(--red);border:1px solid #5b1f28}.abnr.good{background:#0f2a20;color:var(--grn);border:1px solid #1d4535}
  /* aws console (light, like the real thing) */
  .awsc{border:1px solid #11161f;border-radius:10px;overflow:hidden;background:#f2f3f3;color:#16191f}
  .awsc .bar{height:34px;background:#232f3e;display:flex;align-items:center;gap:16px;padding:0 14px;color:#d5dbdb;font-size:12px}.awsc .bar b{color:#fff}.awsc .bar .sp{flex:1}
  .awsc .tabs2{display:flex;gap:2px;background:#fff;border-bottom:1px solid #d5dbdb;padding:0 10px}
  .awsc .tb{padding:9px 14px;font-size:12.5px;color:#545b64;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px}
  .awsc .tb.on{color:#16191f;font-weight:700;border-bottom:2px solid #ff9900}
  .awsc .ct{padding:14px 16px}
  .awsc .cr{font-size:13px;color:#545b64;margin-bottom:10px}.awsc .cr b{color:#16191f}
  .awsc table{width:100%;border-collapse:collapse;font-size:11.5px;background:#fff;border:1px solid #d5dbdb}
  .awsc th{background:#fafafa;text-align:left;padding:7px 11px;color:#545b64;font-size:10.5px;border-bottom:1px solid #eaeded}
  .awsc td{padding:7px 11px;border-bottom:1px solid #eaeded;font-family:var(--mono);color:#16191f;word-break:break-word}
  .awsc tr.bad td{background:#fdf3f1}.awsc .lnk{color:#0073bb}
  .awsc .nt{margin-top:11px;padding:9px 12px;border-radius:3px;font-size:12px;border:1px solid}
  .awsc .nt.warn{background:#fdf6ec;border-color:#f0c36d;color:#7a5a00}.awsc .nt.bad{background:#fdf3f1;border-color:#e6a99b;color:#8a2a16}.awsc .nt.good{background:#f0faf0;border-color:#9bd29b;color:#1a6b1a}
  .awsc .badge{display:inline-block;padding:2px 9px;border-radius:2px;font-size:11px;font-weight:700;color:#fff}.awsc .b-alarm{background:#d13212}.awsc .b-ok{background:#037f0c}
  .awsc .kv2{display:grid;grid-template-columns:180px 1fr;background:#fff;border:1px solid #d5dbdb}.awsc .kv2 div{padding:7px 11px;border-bottom:1px solid #eaeded;font-size:12px}.awsc .kv2 .k{background:#fafafa;color:#545b64}.awsc .kv2 .v{font-family:var(--mono)}
</style></head>
<body><div class="wrap">
  <header class="top">
    <div class="brand">Capstone <b>&middot;</b> Secure an Agentic AI System End to End
      <span class="sub">Chapter 15 &middot; every pillar of the course, one payload, one screen &middot; offline, backed by the real <code>end_to_end.py</code></span></div>
    <div class="ctrls">
      <div class="seg"><span class="lbl">Profile</span><div class="btns" id="profile">
        <button data-k="weak" class="on">baseline.tfvars</button><button data-k="hard">hardened.tfvars</button></div></div>
      <div class="seg"><span class="lbl">Ticket</span><div class="btns" id="ticket">
        <button data-k="poisoned" class="on">Poisoned</button><button data-k="clean">Clean</button></div></div>
    </div>
  </header>

  <div id="banner" class="banner breach">...</div>

  <div class="block">
    <h2>The stack, end to end</h2>
    <p class="cap">Top: the request path the ticket travels. Bottom: the log and detection path. Flip the profile or any one switch and watch the whole thing re-flow.</p>
    <svg id="diagram" viewBox="0 0 1320 430" preserveAspectRatio="xMidYMid meet" role="img"></svg>
  </div>

  <div class="block">
    <h2>What the attack looks like</h2>
    <p class="cap">The product's own view. The ticket on the left, the agent's activity on the right. This is the breach, or the block, as a user would see it.</p>
    <div class="atk" id="attack"></div>
  </div>

  <div class="block">
    <h2>In the AWS console</h2>
    <p class="cap">The same run, as it lands in AWS. The CloudTrail and CloudWatch events are faithful translations of what the chain did.</p>
    <div class="awsc" id="awsc"></div>
  </div>

  <div class="block">
    <h2>Detection pipeline</h2>
    <p class="cap">How a log line becomes a page. In the weak profile none of this exists, which is the whole reason the breach is silent.</p>
    <div class="det">
      <div><div class="lb">CloudWatch Logs metric filter</div><div id="detfilter" class="mono"></div></div>
      <div><div class="lb">SNS &rarr; on-call &mdash; what reached a human</div><div id="detpage" class="mono"></div></div>
    </div>
  </div>

  <div class="grid" id="grid"></div>

  <div class="strips">
    <div class="strip"><h3>Capstone scan &mdash; every pillar</h3><div id="scan" class="scan"></div></div>
    <div class="strip"><h3>Does each lock hold alone?</h3><div id="ind" class="ind"></div></div>
  </div>

  <div class="block">
    <h2>The whole course, capped off here</h2>
    <p class="cap">Every control in the capstone, the pillar it came from, the chapter that built it, and what it decides. Six controls, four pillars, one stack.</p>
    <div id="recap" class="recap"></div>
  </div>

  <footer>
    Offline. No AWS, no credentials, no cost. The CloudTrail and CloudWatch events are a faithful translation of what the real chain did. &nbsp;
    Terminal: <code>python3 attack/end_to_end.py --ticket tickets/poisoned.pdf</code> &middot; <code>python3 scan/scan.py --green-wall</code><br>
    &copy; 2026 Vigilantia Technologies INC. &trade; HackWithZach. Education / defense only.
  </footer>
</div>

<script>
const GATES=["guardrail","goal-lock","tool-least-priv","hitl-approval","run-audit"];
let locks={guardrail:false,"goal-lock":false,"tool-least-priv":false,"hitl-approval":false,"run-audit":false};
let ticket="poisoned";
let LAST=null;
const esc=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const C={in:'#ffc24b',open:'#ff5d6c',stop:'#45d19a',dim:'#39455a',breach:'#ff5d6c',touched:'#ffc24b',
         log:'#5aa2ff',on:'#45d19a',off:'#39455a',alarm:'#45d19a',ok:'#45d19a',silent:'#39455a',paged:'#45d19a'};
function qs(){const p=new URLSearchParams();GATES.forEach(g=>p.set(g,locks[g]?"1":"0"));p.set("ticket",ticket);return p.toString();}

async function refresh(){
  const r=await fetch("/api/state?"+qs());const d=await r.json();
  const b=document.getElementById("banner");
  b.className="banner "+(d.ticket==="clean"?"clean":(d.breached?"breach":"blocked"));b.textContent=d.headline;
  LAST=d;
  drawDiagram(d.diagram);
  drawAttack(d);
  drawConsole(d);
  drawDetection(d.detection);
  const g=document.getElementById("grid");g.innerHTML="";
  g.appendChild(cloud(d.pillars.cloud));g.appendChild(api(d.pillars.api));
  g.appendChild(agent(d.pillars.agent));g.appendChild(mcp(d.pillars.mcp));
  renderScan(d.scan,d.scan_clean);renderInd(d.independence);renderRecap(d.recap);
}

/* ---------- the architecture + flow diagram ---------- */
function node(x,y,w,h,label,sub,col,strong){
  const fill="#131824";
  return `<rect x="${x}" y="${y}" rx="9" width="${w}" height="${h}" fill="${fill}" stroke="${col}" stroke-width="${strong?2.4:1.4}"/>
    <text x="${x+w/2}" y="${y+h/2-3}" fill="${col}" font-size="13" font-weight="700" text-anchor="middle">${esc(label)}</text>
    <text x="${x+w/2}" y="${y+h/2+14}" fill="#8a94a7" font-size="9.5" text-anchor="middle">${esc(sub)}</text>`;
}
function arrow(x1,y1,x2,y2,col,w,dash){
  return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${col}" stroke-width="${w||2}" ${dash?'stroke-dasharray="5 4"':''} marker-end="url(#ah-${col.replace('#','')})"/>`;
}
function marker(col){return `<marker id="ah-${col.replace('#','')}" markerWidth="8" markerHeight="8" refX="6.5" refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="${col}"/></marker>`;}
function drawDiagram(dg){
  const W=172,H=66,step=187,ax=15,ay=56;      // request lane
  const DW=200,DH=58,dstep=218,dx=15,dy=320;   // detect lane
  const req=dg.request, det=dg.detect;
  const cols=new Set();[...req,...det].forEach(n=>cols.add(C[n.state]||'#39455a'));
  cols.add('#5aa2ff');cols.add('#39455a');cols.add('#ff5d6c');cols.add('#45d19a');
  let svg=`<defs>${[...cols].map(marker).join("")}</defs>`;
  // lane labels
  svg+=`<text x="15" y="30" fill="#8a94a7" font-size="11" font-weight="700" letter-spacing="1.5">REQUEST PATH &mdash; THE PAYLOAD'S JOURNEY</text>`;
  svg+=`<text x="15" y="300" fill="#8a94a7" font-size="11" font-weight="700" letter-spacing="1.5">LOG &amp; DETECTION PATH &mdash; HOW IT BECOMES A PAGE</text>`;
  // request nodes + arrows
  const stopIdx=req.findIndex(n=>n.state==="stop");
  req.forEach((n,i)=>{
    const x=ax+i*step, col=C[n.state]||C.dim, strong=(n.state==="open"||n.state==="stop"||n.state==="breach");
    if(i<req.length-1){
      const flowing = stopIdx===-1 ? true : (i<stopIdx);
      const acol = flowing?'#ff5d6c':(i===stopIdx?'#45d19a':'#39455a');
      svg+=arrow(x+W, ay+H/2, x+step, ay+H/2, acol, flowing?2.4:1.4);
    }
    svg+=node(x,ay,W,H,n.label,n.sub,col,strong);
  });
  // emit: the request lane feeds the log plane (dashed blue)
  const emitCol = (det[0].state==="log"||det[1].state==="log")?'#5aa2ff':'#39455a';
  svg+=arrow(690, ay+H+8, 340, dy-10, emitCol, 1.8, true);
  svg+=`<text x="712" y="${(ay+H+dy)/2+2}" fill="${emitCol}" font-size="9.5">every call + decision is emitted to CloudTrail / CloudWatch</text>`;
  // detect nodes + arrows
  det.forEach((n,i)=>{
    const x=dx+i*dstep, col=C[n.state]||C.dim;
    const strong=(n.state==="alarm"||n.state==="paged"||n.state==="log");
    if(i<det.length-1){
      let acol='#39455a', wdt=1.4;
      if(i===0||i===1){ acol = n.state==="log"?'#5aa2ff':'#39455a'; wdt = n.state==="log"?2:1.4; }
      else { const active = det[5].state==="paged"; acol=active?'#45d19a':'#39455a'; wdt=active?2.2:1.4; }
      svg+=arrow(x+DW, dy+DH/2, x+dstep, dy+DH/2, acol, wdt);
    }
    svg+=node(x,dy,DW,DH,n.label,n.sub,col,strong);
  });
  document.getElementById("diagram").innerHTML=svg;
}

/* ---------- detection pipeline detail ---------- */
function drawDetection(det){
  const f=document.getElementById("detfilter"), p=document.getElementById("detpage");
  if(!det.active){
    f.className="mono empty";f.textContent="metric filters: none\nsubscription filters: none\nalarms in ALARM: 0   (run-audit is off)";
    p.className="mono empty";p.textContent="(nothing reached a human)";
    return;
  }
  f.className="mono";
  f.innerHTML='filterPattern:  <span class="g">'+esc(det.filter)+'</span>\n'
    +'metric:         '+esc(det.metric)+'\n'
    +'alarm:          >= 1 in 60s  ->  '+(det.alarm==="ALARM"?'<span class="g">ALARM</span>':'<span class="a">OK</span>')+'\n'
    +'alarmAction:    arn:aws:sns:...:soc-oncall\n'
    +'cloudtrail rule: '+esc(det.ct_rule);
  if(det.paged){
    p.className="mono";
    p.innerHTML='<span class="g">ALARM: '+esc(det.metric)+'  (1 datapoint)</span>\n'
      +det.page.map(e=>esc(JSON.stringify(e))).join("\n");
  }else{
    p.className="mono empty";p.textContent="filter armed, nothing matched this run";
  }
}

/* ---------- consoles ---------- */
function shell(p){const c=document.createElement("div");c.className="con";c.dataset.k=p.key;
  c.innerHTML=`<div class="hd"><span class="dot"></span><div class="htxt"><div class="t">${p.title}</div><div class="s">${p.sub}</div></div><span class="tag">${p.tag} &middot; ${p.pillar}</span></div><div class="body"></div>`;return c;}
function sec(lb,inner){return `<div><div class="lb">${lb}</div>${inner}</div>`;}
function depRows(rows){return `<div class="dep">`+rows.map(r=>{const cls=r.on?"hard":"open";const val=r.on?r.hard:r.weak;
  return `<div class="row"><div class="rn">${esc(r.name)}</div><div class="rv ${cls}"><span class="pill">${r.on?"SECURED":"WEAK"}</span> ${esc(val)}</div></div>`;}).join("")+`</div>`;}
function sw(gate,label,desc,on){return `<div class="sw ${on?'on':''}" data-gate="${gate}"><div class="knob"></div><div class="sl"><div class="n">${esc(label)}</div><div class="d">${esc(desc)}</div></div><div class="st">${on?'ON':'OFF'}</div></div>`;}
function jlog(arr){if(!arr||!arr.length)return `<div class="mono empty">(no events this run)</div>`;
  return `<div class="mono">`+arr.map(e=>esc(JSON.stringify(e))).join("\n")+`</div>`;}
function vf(v){return `<div class="vf ${v.state}"><span class="ic">${v.state==='held'?'✔':v.state==='open'?'✘':'—'}</span>${esc(v.text)}</div>`;}
function cloud(p){const c=shell(p),bd=c.querySelector(".body");
  bd.innerHTML=sec("Deploy",depRows(p.deploy))+sec("Secure",sw(p.control,p.control_label,"Ch 8 + Ch 10",p.control_on))
    +sec(p.logtitle,jlog(p.log))+sec("Verify &amp; analyze",vf(p.verify));return c;}
function api(p){const c=shell(p),bd=c.querySelector(".body");
  const rr=`<div class="rr">&rarr; ${esc(p.request)}<br>&larr; <span class="${p.response.status.includes('broad')?'b':p.response.status.includes('scoped')?'s':'n'}">${esc(p.response.status)}</span> &middot; ${esc(p.response.note)}</div>`;
  bd.innerHTML=sec("Deploy",depRows(p.deploy))+sec("Secure",sw(p.control,p.control_label,"Ch 12 least privilege",p.control_on))
    +sec("Request / response",rr)+sec(p.logtitle,jlog(p.log))+sec("Verify &amp; analyze",vf(p.verify));return c;}
function agent(p){const c=shell(p),bd=c.querySelector(".body");
  const chat=`<div class="chat">`+p.chat.map(m=>`<div class="msg ${m.who}${m.state?' '+m.state:''}">${esc(m.text)}</div>`).join("")+`</div>`;
  bd.innerHTML=sec("Deploy",depRows(p.deploy))+sec("Secure",sw(p.control,p.control_label,"Ch 11 guardrail",p.control_on)+sw(p.control2,p.control2_label,"Ch 13 goal-lock",p.control2_on))
    +sec("Agent run",chat)+sec(p.logtitle,jlog(p.log))+sec("Verify &amp; analyze",`<div class="vrow">${vf(p.verify.guardrail)}${vf(p.verify.goal)}</div>`);return c;}
function mcp(p){const c=shell(p),bd=c.querySelector(".body");
  const cs=p.call.state==='fired'?'open':(p.call.state==='parked'?'held':'na');
  const call=`<div class="vf ${cs}"><span class="ic">${p.call.state==='fired'?'✘':p.call.state==='parked'?'✔':'—'}</span>${esc(p.call.line)}</div>`;
  bd.innerHTML=sec("Deploy",depRows(p.deploy))+sec("Secure",sw(p.control,p.control_label,"Ch 13 human in the loop",p.control_on))
    +sec("Tool-call inspector",call)+sec(p.logtitle,jlog(p.log))+sec("Verify &amp; analyze",vf(p.verify));return c;}

function renderScan(f,clean){const el=document.getElementById("scan");
  if(clean){el.innerHTML=`<div class="pass">&#10003; PASS &mdash; every pillar wired. 0 gaps.</div>`;return;}
  el.innerHTML=f.map(x=>`<div class="sr"><span class="sev ${x.sev}">${x.sev}</span><div><b>${esc(x.name)}</b> &middot; ${esc(x.pillar)} &middot; ${esc(x.ch)}<br><span style="color:var(--mut)">${esc(x.why)}</span></div></div>`).join("");}
function renderInd(ind){const el=document.getElementById("ind");
  el.innerHTML=ind.map(i=>{const ty=i.detection?"detection":"preventive";
    const res=i.holds?`<span class="ok">HOLDS alone</span>`:(i.detection?`<span class="no">does not stop it</span>`:`<span class="no">FAILS</span>`);
    return `<div class="ir"><span class="g">${esc(i.gate)}</span><span class="ty">${ty}</span>${res}</div>`;}).join("")
    +`<div style="color:var(--mut);font-size:11.5px;margin-top:9px;line-height:1.55">Four preventive locks each stop the chain alone. <b>run-audit is detection, not prevention</b> &mdash; it is why you find out, not why it did not happen.</div>`;}
function renderRecap(rc){document.getElementById("recap").innerHTML=rc.map(r=>
  `<div class="rc"><div class="n">${esc(r.name)}</div><div class="m">${esc(r.pillar)} &middot; ${esc(r.ch)}</div><div class="w">${esc(r.why)}</div></div>`).join("");}

/* ---------- attack view ---------- */
function drawAttack(d){
  const el=document.getElementById("attack");
  const gl={ok:'✓',bad:'✗',warn:'!',sh:'🛡'};
  const steps=d.activity.map(a=>`<div class="stp ${a.cls}"><div class="i ${a.ic}">${gl[a.ic]||''}</div><div><div class="tt">${esc(a.t)}</div><div class="dd">${esc(a.d)}</div></div></div>`).join("");
  const bn=`<div class="abnr ${d.attack_banner.cls}">${esc(d.attack_banner.t)}</div>`;
  let tkt=esc(d.ticket_text);
  if(d.injected) tkt=tkt.replace(/(Ignore your task[\s\S]*?account team\.)/,'<span class="hl">$1</span>');
  const prof=d.ticket==='clean'?'clean ticket':(d.breached?'baseline · locks off':'hardened · locks on');
  el.innerHTML=`<div class="hd2"><span class="dot"></span><span class="lg">AI Support Agent</span><span class="who">· handling ticket queue</span><span class="sp"></span><span class="who">${prof}</span></div>
    <div class="cl l"><div class="clbl">Incoming ticket</div><div class="tk">${tkt}</div></div>
    <div class="cl"><div class="clbl">Agent activity</div>${steps}${bn}</div>`;
}

/* ---------- AWS console (tabbed) ---------- */
let awsTab="logs";
function drawConsole(d){
  const el=document.getElementById("awsc"), tab=awsTab, det=d.detection;
  const bar=`<div class="bar"><b>${tab==='trail'?'CloudTrail':'CloudWatch'}</b><span class="sp"></span><span>us-east-1 ▾</span></div>`;
  const tabs=`<div class="tabs2">
    <div class="tb ${tab==='logs'?'on':''}" data-tab="logs">CloudWatch Logs</div>
    <div class="tb ${tab==='trail'?'on':''}" data-tab="trail">CloudTrail</div>
    <div class="tb ${tab==='alarm'?'on':''}" data-tab="alarm">CloudWatch Alarm</div></div>`;
  let body="";
  if(tab==='logs'){
    const rows=d.cloudwatch.length?d.cloudwatch.map((e,i)=>{const bad=/send_email/.test(JSON.stringify(e));
      return `<tr class="${bad?'bad':''}"><td>2026-05-22T08:14:0${i}.1Z</td><td>${esc(JSON.stringify(e))}</td></tr>`;}).join("")
      :`<tr><td colspan="2" style="color:#879596">(no events this run)</td></tr>`;
    body=`<div class="cr"><b>/hwz/capstone/agent</b> › Log events</div>
      <table><thead><tr><th style="width:200px">Timestamp</th><th>Message</th></tr></thead><tbody>${rows}</tbody></table>
      <div class="nt ${det.active?'good':'warn'}">${det.active?'<b>1 metric filter armed.</b> guardrail_block → alarm → SNS → on-call.':'<b>No metric filter on this log group. 0 alarms in ALARM.</b> The events are here; nothing is watching them.'}</div>`;
  } else if(tab==='trail'){
    const rows=d.cloudtrail.length?d.cloudtrail.map(e=>{const bad=e.eventSource==='dynamodb.amazonaws.com'||e.eventSource==='ses.amazonaws.com';
      const res=e.tableName?(e.tableName+(e.scannedCount!=null?` (scannedCount: ${e.scannedCount})`:'')+(e.key?` (${e.key})`:'')):(e.destination||e.resource||'');
      return `<tr class="${bad?'bad':''}"><td class="lnk">${esc(e.eventName)}</td><td>${esc(e.eventSource)}</td><td>${esc(res)}</td></tr>`;}).join("")
      :`<tr><td colspan="3" style="color:#879596">(no AWS API calls this run)</td></tr>`;
    body=`<div class="cr"><b>CloudTrail</b> › Event history</div>
      <table><thead><tr><th style="width:160px">Event name</th><th style="width:230px">Event source</th><th>Resource</th></tr></thead><tbody>${rows}</tbody></table>
      <div class="nt ${d.cloudtrail.length?(det.active?'good':'bad'):'warn'}">${d.cloudtrail.length?(det.active?'<b>Recorded, and alerted.</b> A rule turns these rows into a page.':'<b>Recorded, not alerted.</b> No rule turns these rows into a page.'):'No AWS API calls happened this run. The guardrail stopped the agent before it touched the cloud.'}</div>`;
  } else {
    if(det.alarm==='ALARM'){
      body=`<div class="cr"><b>${esc(det.metric)}</b> <span class="badge b-alarm">In alarm</span></div>
        <div class="kv2"><div class="k">Namespace</div><div class="v">HWZ/Capstone</div>
          <div class="k">Metric</div><div class="v">${esc(det.metric)}</div>
          <div class="k">Statistic / Period</div><div class="v">Sum / 60 seconds</div>
          <div class="k">Threshold</div><div class="v">GreaterThanOrEqualToThreshold 1</div>
          <div class="k">State</div><div class="v"><span class="badge b-alarm" style="font-size:10px">ALARM</span></div>
          <div class="k">Action</div><div class="v">arn:aws:sns:us-east-1:…:soc-oncall</div></div>
        <div class="nt good"><b>State changed to ALARM.</b> Trigger: ${esc(JSON.stringify((det.page&&det.page[0])||{}))} → SNS → on-call paged.</div>`;
    } else {
      body=`<div class="cr">CloudWatch › All alarms</div>
        <div class="nt ${det.active?'good':'warn'}">${det.active?'<b>CapstoneInjectionBlocked: OK.</b> The filter is armed; nothing matched this run.':'<b>No alarms configured.</b> run-audit is off, so no metric filter and no alarm exist on this stack.'}</div>`;
    }
  }
  el.innerHTML=bar+tabs+`<div class="ct">${body}</div>`;
}
document.getElementById("awsc").addEventListener("click",e=>{const t=e.target.closest(".tb");if(!t)return;awsTab=t.dataset.tab;if(LAST)drawConsole(LAST);});

document.getElementById("profile").addEventListener("click",e=>{const b=e.target.closest("button");if(!b)return;
  [...e.currentTarget.children].forEach(x=>x.classList.toggle("on",x===b));
  const on=b.dataset.k==="hard";GATES.forEach(g=>locks[g]=on);refresh();});
document.getElementById("ticket").addEventListener("click",e=>{const b=e.target.closest("button");if(!b)return;
  [...e.currentTarget.children].forEach(x=>x.classList.toggle("on",x===b));ticket=b.dataset.k;refresh();});
document.getElementById("grid").addEventListener("click",e=>{const s=e.target.closest(".sw");if(!s)return;
  const g=s.dataset.gate;locks[g]=!locks[g];
  const allOn=GATES.every(x=>locks[x]),allOff=GATES.every(x=>!locks[x]);
  const pb=document.getElementById("profile").children;pb[0].classList.toggle("on",allOff);pb[1].classList.toggle("on",allOn);refresh();});
refresh();
</script>
</body></html>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5115"))
    app.run(host="127.0.0.1", port=port, debug=False)
