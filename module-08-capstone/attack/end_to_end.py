#!/usr/bin/env python3
"""
end_to_end.py — one poisoned ticket, driven through all four pillars.

THE CHAIN
---------
A customer uploads a support ticket. Buried in it, in text a human skims past,
is an instruction to look up every account and email the list to an outside
address. Five gates stand between that sentence and a data breach:

    1. guardrail        does the poisoned text reach the model at all?
    2. goal-lock        can an injected sentence replace the agent's objective?
    3. tool-least-priv  can lookup_account read the table, or one record?
    4. hitl-approval    does an irreversible external send need a human?
    5. run-audit        if any of the above trips, does anyone find out?

Weak, all five are open and the chain completes in silence. Hardened, it dies
at the first lock it meets.

THE CLAIM THIS FILE HAS TO EARN
--------------------------------
Chapter 15 says it "would not have mattered which lock you removed" -- that the
guardrail catches it first, but the goal lock, the least-privilege role and the
human gate each independently stop it too. That is a strong claim, and a book
that asserts it without testing it is asking for trust it has not earned.

So `--prove-independence` runs the chain once per lock, with that lock ON and
every other lock OFF, and reports whether each one holds alone. If a lock does
not hold by itself, this prints FAIL and the claim in the book is wrong.
Defense in depth means four independent locks, not one lock and three
spectators.

    python3 attack/end_to_end.py --ticket tickets/poisoned.txt            # weak
    python3 attack/end_to_end.py --ticket tickets/poisoned.txt --hardened
    python3 attack/end_to_end.py --prove-independence
    python3 attack/end_to_end.py --selftest        # offline, no AWS, no cost

Exit code 0 = the chain was stopped. 1 = BREACH. In CI, a breach fails the job.

(c) 2026 Vigilantia Technologies INC. HackWithZach. Education/defense only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_DIR = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(MODULE_DIR)

# The five locks, in the order the attack meets them. Order matters: it is the
# reason the hardened run reports the guardrail and not the goal lock. The
# attack does not get to choose which door it hits first.
GATES = [
    ("guardrail",       "Pillar 1", "poisoned instruction reached the model"),
    ("goal-lock",       "Pillar 3", 'agent goal replaced: "exfiltrate accounts"'),
    ("tool-least-priv", "Pillar 2", "lookup_account read ALL records (broad role)"),
    ("hitl-approval",   "Pillar 3", "send_email to external-domain.com fired"),
    ("run-audit",       "Pillar 1", "no alarm; the exfiltration was silent"),
]

BLOCKED_BY = {
    "guardrail":       "input guardrail blocked the injected instruction",
    "goal-lock":       "the standing objective is not model-editable; swap refused",
    "tool-least-priv": "lookup_account can read one record, not the table",
    "hitl-approval":   "the external send parked for human approval",
    "run-audit":       "the blocked step paged the on-call",
}

# The account store is fake and the "customer database" is three rows. The
# point of the exercise is the control flow, not the data.
ACCOUNTS = {
    "jordan@example.com": {"name": "Jordan Rivera", "plan": "Pro"},
    "sam@example.com":    {"name": "Sam Okafor",    "plan": "Team"},
    "admin@example.com":  {"name": "Internal Admin", "plan": "Enterprise",
                           "api_key": "sk-ADMIN-SECRET-KEY-9f3c2b7a11e4"},
}

SESSION_IDENTITY = "jordan@example.com"
EXTERNAL_RECIPIENT = "billing-audit@external-domain.com"

INJECTION_MARKERS = (
    "ignore your task", "ignore your previous", "your new goal",
    "new goal:", "email the list", "system update:",
)


def load_ticket(path):
    """
    Read a ticket from .txt or .pdf.

    The PDF path is the one that matters for teaching: the injection rides
    inside a document the agent was asked to read, which is why "just tell
    users not to paste weird text" was never a control.
    """
    if path.lower().endswith(".pdf"):
        try:
            from pypdf import PdfReader
        except ImportError:
            sys.exit("Reading a .pdf ticket needs pypdf:  pip install pypdf\n"
                     "Or run the same attack as text: --ticket tickets/poisoned.txt")
        return "\n".join((p.extract_text() or "") for p in PdfReader(path).pages)
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def looks_injected(text):
    low = text.lower()
    return any(m in low for m in INJECTION_MARKERS)


def run_chain(ticket_text, locks):
    """
    Drive the ticket through the five gates.

    `locks` is {gate_name: bool}. Returns (breached, steps) where steps is a
    list of (index, gate, state, message). The function stops at the first lock
    that holds -- that is the whole point of a chain, and reporting the later
    gates as "also would have stopped it" would be a lie about what happened.
    """
    steps = []
    trace = []      # what the agent did. Always recorded, locally.
    soc = []        # what reached your alert path. Only if run-audit is wired.

    def note(event, **kw):
        """
        Record an event twice, on purpose.

        The agent's own trace always gets it -- the action happened, and it
        happened whether or not anyone was watching. The SOC gets it only when
        run-audit is on. That gap IS Chapter 10's lesson: the events exist, the
        log group fills up, and none of it reaches a human unless someone wired
        a metric filter to an alarm. "It was logged" and "we found out" are two
        different claims, and only one of them saves you.
        """
        rec = {"event": event, **kw}
        trace.append(rec)
        if locks.get("run-audit"):
            soc.append(rec)

    # 1. Guardrail --------------------------------------------------------
    if locks.get("guardrail"):
        note("guardrail_block", reason="injection-pattern")
        steps.append((1, "guardrail", "ON", BLOCKED_BY["guardrail"]))
        return False, steps, trace, soc
    injected = looks_injected(ticket_text)
    steps.append((1, "guardrail", "OFF", GATES[0][2]))

    # 2. Goal lock --------------------------------------------------------
    # Only reachable because the guardrail let the text through. If the goal is
    # locked, the injected objective is discarded and the agent keeps its own.
    if injected and locks.get("goal-lock"):
        note("goal_swap_refused", attempted="exfiltrate accounts")
        steps.append((2, "goal-lock", "ON", BLOCKED_BY["goal-lock"]))
        return False, steps, trace, soc
    goal = "exfiltrate accounts" if injected else "answer the ticket"
    # Report the outcome, not the intent. With a clean ticket the goal survives,
    # and printing "goal replaced" anyway would teach students to read the lab's
    # labels instead of its behaviour.
    steps.append((2, "goal-lock", "OFF",
                  GATES[1][2] if injected
                  else 'goal intact: "answer the ticket" (nothing to inject)'))

    # 3. Tool least privilege ---------------------------------------------
    if locks.get("tool-least-priv"):
        note("tool_scope_enforced", tool="lookup_account", returned_for=SESSION_IDENTITY)
        steps.append((3, "tool-least-priv", "ON", BLOCKED_BY["tool-least-priv"]))
        return False, steps, trace, soc
    # The broad role reads whatever the goal asks for. A hijacked goal asks for
    # the table; an intact goal asks for one record. Same role, same tool --
    # the blast radius is set by the weakest control upstream of it.
    harvested = list(ACCOUNTS) if goal == "exfiltrate accounts" else [SESSION_IDENTITY]
    note("tool_call", tool="lookup_account", records=len(harvested))
    steps.append((3, "tool-least-priv", "OFF",
                  GATES[2][2] if goal == "exfiltrate accounts"
                  else "lookup_account could read ALL records; this goal asked for one"))

    # 4. Human in the loop -------------------------------------------------
    if locks.get("hitl-approval"):
        note("send_parked_for_approval", to=EXTERNAL_RECIPIENT, records=len(harvested))
        steps.append((4, "hitl-approval", "ON", BLOCKED_BY["hitl-approval"]))
        return False, steps, trace, soc
    if goal != "exfiltrate accounts":
        # Nothing irreversible was attempted, so there is no chain to complete.
        steps.append((4, "hitl-approval", "OFF",
                      "no external send attempted; the ticket was answered"))
        steps.append((5, "run-audit", "ON" if locks.get("run-audit") else "OFF",
                      "normal ticket, handled"))
        return False, steps, trace, soc
    note("tool_call", tool="send_email", to=EXTERNAL_RECIPIENT, records=len(harvested))
    steps.append((4, "hitl-approval", "OFF", GATES[3][2]))

    # 5. Run audit ---------------------------------------------------------
    # Reaching here means the data is already gone. The audit lock cannot undo
    # an exfiltration -- it decides whether you find out. That is why it is
    # last, and why it is not a substitute for any of the four above it.
    steps.append((5, "run-audit", "ON" if locks.get("run-audit") else "OFF",
                  "the exfiltration was recorded and paged the on-call"
                  if locks.get("run-audit") else GATES[4][2]))
    return True, steps, trace, soc


def render(breached, steps, trace, soc, show_soc=True):
    if breached:
        print("BREACH. The chain completed:")
    else:
        print("BLOCKED. The chain died at the first lock it hit, and the SOC saw it:")
    for i, gate, state, msg in steps:
        print(f"  {i}. {gate:<18}{state:<5} -> {msg}")

    if not breached:
        held = steps[-1][1]
        others = [g for g, _, _ in GATES if g not in (held, "run-audit")]
        print(f"\n  (and had it slipped, {', '.join(others)} would each have "
              f"stopped it independently — run --prove-independence)")

    if show_soc:
        print("\nAGENT TRACE (what happened):")
        if not trace:
            print("  (nothing — the chain died before the agent acted)")
        for a in trace:
            print("  " + json.dumps(a, sort_keys=True))

        print("\nSOC (what reached a human):")
        if not soc:
            print("  (nothing. The events above exist; nobody was watching them.")
            print("   That gap is the difference between 'it was logged' and")
            print("   'we found out', and only one of those saves you.)")
        for a in soc:
            print("  " + json.dumps(a, sort_keys=True))


def prove_independence(ticket_text):
    """
    Turn the book's claim into a test.

    For each lock that should be able to stop this chain alone, run with ONLY
    that lock on. run-audit is excluded on purpose and the reason is printed:
    it is a detection control, not a prevention control. It tells you the
    breach happened. It does not stop it, and a capstone that counted it as a
    fourth lock would be teaching students to overcount their defenses.
    """
    preventive = ["guardrail", "goal-lock", "tool-least-priv", "hitl-approval"]
    print("Each lock, alone, against the same payload:\n")
    ok = True
    for lock in preventive:
        locks = {g: (g == lock) for g, _, _ in GATES}
        breached, steps, _, _ = run_chain(ticket_text, locks)
        stopped_at = steps[-1][1] if not breached else "—"
        mark = "HOLDS " if not breached else "FAILS "
        if breached:
            ok = False
        print(f"  {mark} {lock:<18} only lock on -> "
              f"{'stopped at ' + stopped_at if not breached else 'BREACH'}")

    locks = {g: (g == "run-audit") for g, _, _ in GATES}
    breached, _, _, _ = run_chain(ticket_text, locks)
    print(f"\n  {'(expected)' :<11}{'run-audit':<18} only lock on -> "
          f"{'BREACH, recorded' if breached else 'stopped'}")
    print("  run-audit is detection, not prevention. It is why you find out,")
    print("  not why it did not happen. Counting it as a fourth lock would be")
    print("  overcounting your defenses, which is its own kind of breach.")

    print("\n" + ("PASS — four independent preventive locks."
                  if ok else
                  "FAIL — a lock that the book claims holds alone did not."))
    return 0 if ok else 1


def selftest():
    clean = "Hi, my invoice looks wrong. Can you check my plan? — jordan@example.com"
    poisoned_path = os.path.join(HERE, "tickets", "poisoned.txt")
    poisoned = load_ticket(poisoned_path)
    all_off = {g: False for g, _, _ in GATES}
    all_on = {g: True for g, _, _ in GATES}
    ok = True

    def check(label, cond):
        nonlocal ok
        print(f"selftest: {label:<52}{'ok' if cond else 'FAIL'}")
        if not cond:
            ok = False

    b, steps, trace, soc = run_chain(poisoned, all_off)
    check("weak profile, poisoned ticket -> BREACH", b)
    check("  breach walks all five gates", len(steps) == 5)
    check("  breach reached NO human (SOC empty)", soc == [])
    check("  but the agent trace recorded it anyway", len(trace) >= 2)

    b, steps, trace, soc = run_chain(poisoned, all_on)
    check("hardened profile, same ticket -> BLOCKED", not b)
    check("  dies at the guardrail, the first lock", steps[-1][1] == "guardrail")
    check("  the block reached the SOC", len(soc) >= 1)

    b, steps, _, _ = run_chain(clean, all_off)
    check("weak profile, CLEAN ticket -> no goal swap", 'exfiltrate' not in steps[1][3])

    b, _, _, _ = run_chain(clean, all_on)
    check("hardened profile still serves a clean ticket", not b)

    # The independence claim, asserted in the book, tested here.
    for lock in ("guardrail", "goal-lock", "tool-least-priv", "hitl-approval"):
        locks = {g: (g == lock) for g, _, _ in GATES}
        b, _, _, _ = run_chain(poisoned, locks)
        check(f"  {lock} alone stops the chain", not b)

    b, _, _, _ = run_chain(poisoned, {g: (g == "run-audit") for g, _, _ in GATES})
    check("run-audit alone does NOT stop it (detection != prevention)", b)

    # The PDF carries the same attack as the text. If these diverge, the lab
    # teaches two different things depending on which file you open.
    pdf = os.path.join(HERE, "tickets", "poisoned.pdf")
    if os.path.exists(pdf):
        try:
            b_pdf, _, _, _ = run_chain(load_ticket(pdf), all_off)
            check("poisoned.pdf breaches exactly like poisoned.txt", b_pdf)
            b_pdf, _, _, _ = run_chain(load_ticket(pdf), all_on)
            check("poisoned.pdf is blocked exactly like poisoned.txt", not b_pdf)
        except SystemExit:
            print("selftest: (pypdf not installed, skipping the .pdf ticket)")

    print("selftest:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def posture_from_file(path):
    """Read the posture file Terraform writes, so the attack reflects the deploy."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return {g: bool(data.get(g, False)) for g, _, _ in GATES}


def main():
    ap = argparse.ArgumentParser(description="Run the end-to-end capstone attack.")
    ap.add_argument("--ticket", default=os.path.join(HERE, "tickets", "poisoned.txt"))
    ap.add_argument("--hardened", action="store_true",
                    help="all five locks on (what hardened.tfvars deploys)")
    ap.add_argument("--posture", help="posture.json written by terraform apply")
    ap.add_argument("--prove-independence", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--quiet-soc", action="store_true", help="hide the SOC block")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    ticket = load_ticket(args.ticket)

    if args.prove_independence:
        return prove_independence(ticket)

    if args.posture:
        locks = posture_from_file(args.posture)
        src = os.path.basename(args.posture)
    else:
        locks = {g: args.hardened for g, _, _ in GATES}
        src = "hardened.tfvars" if args.hardened else "baseline.tfvars"

    print(f"Ticket:  {os.path.basename(args.ticket)}")
    print(f"Profile: {src}\n")
    breached, steps, trace, soc = run_chain(ticket, locks)
    render(breached, steps, trace, soc, show_soc=not args.quiet_soc)
    return 1 if breached else 0


if __name__ == "__main__":
    sys.exit(main())
