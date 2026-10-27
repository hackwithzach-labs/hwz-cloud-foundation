# Chapter 15 - Capstone visual lab

```bash
pip install -r requirements.txt
python app.py            # http://localhost:5115
```

Port is `5100 + chapter`, like every visual lab here.

The big one. The whole course on one screen, driven by one payload.

- **The stack, end to end.** A live architecture diagram in two lanes. The top
  lane is the request path the ticket travels: Ticket, Guardrail, Agent,
  Goal-lock, lookup_account, send_email over MCP, Cloud data. The bottom lane is
  the log and detection path: CloudTrail and CloudWatch Logs, then metric
  filter, alarm, SNS, on-call. Weak, the request lane runs red all the way to a
  breach and the detection lane stays dark. Hardened, the request lane stops
  green at the guardrail and the detection lane lights all the way to a page.
- **Detection pipeline.** The real CloudWatch Logs metric filter pattern, the
  alarm state, and the exact message that reaches a human. Silent when weak,
  because none of it exists; firing when hardened.
- **Four pillar consoles.** Cloud, API, Agent, MCP. Each shows deploy state, a
  secure switch, and the actual CloudTrail or CloudWatch JSON this run produced.
- **Capstone scan and independence proof.** Every pillar in one report, and
  whether each lock holds alone.
- **The whole course, capped off.** Every control, its pillar, the chapter that
  built it, and what it decides.

Flip **Profile** to move the whole stack at once, or flip any one pillar's
switch and watch only that gate change and the diagram re-flow. Flip **Ticket**
to Clean to confirm the hardened stack still answers a normal ticket.

Offline. No AWS, no credentials, no cost. It looks and teaches like AWS, but it
contains no logic of its own: it imports `../attack/end_to_end.py` and
`../scan/scan.py` and renders what they return. The CloudTrail and CloudWatch
events are a faithful translation of what the real chain did into the AWS API
calls those actions make, so the browser and the terminal cannot disagree.

(c) 2026 Vigilantia Technologies INC. (TM) HackWithZach.
