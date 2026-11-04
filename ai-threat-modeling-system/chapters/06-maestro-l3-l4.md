kicker: WEEK 3 · LESSON A06
title: MAESTRO Layers 3 and 4.
summary: Agent frameworks and the infrastructure they run on. Where the model acquires authority, where that authority is scoped or not, and why most agentic breaches are privilege bugs wearing a prompt-injection costume.

## Layer 3: agent frameworks

L3 is the code around the model: the loop that reads its output, the registry of tools it can call, the way its reply is turned into an action, the goal it is pursuing, and the gates that stand between its intent and the world. This is the layer where "the model said X" becomes "the system did X", and it is the layer where almost every real agentic incident is decided.

The capstone was built as five gates, and four of them are L3 controls:

| Gate | L3 concern | Register |
|---|---|---|
| 2 goal-lock | Is the objective writable from a model turn? | CAP-02 |
| 3 tool-least-priv | Does each tool run with the caller's scope or the system's? | CAP-03 |
| 4 hitl-approval | Does an irreversible action need a human? | CAP-04 |
| (none) | Is there a ceiling on iterations and spend per run? | CAP-10 |

Gate 1 (guardrail) sits between L2 and L1, which is why it was in the last lesson. Gate 5 (run-audit) is L5, next lesson.

**Goal integrity (CAP-02).** The agent's standing objective, "answer the ticket", lives somewhere. If it lives in the same context the model writes to, a model turn can replace it, and the capstone's baseline run shows it replaced with "exfiltrate accounts". The control is to hold the objective outside the model's writable state, set by the operator, and to treat any attempt to change it as an event to refuse and log. In STRIDE terms this is Tampering with control state, and in the Agentic Top 10 it is the headline entry, ASI01 Agent Goal Hijack. CWE-807, reliance on untrusted inputs in a security decision, is the closest classic weakness.

**Tool authority (CAP-03).** `lookup_account` can return one record or the table, and the difference is whether the tool's role is bound to the session identity. In the baseline it is broad, so the hijacked goal reads every account, including `admin@example.com` with its `api_key` field. This is the row to use when a client says "but we have a guardrail": the guardrail is one lock, and the tool scope is an independent one, and `--prove-independence` shows the tool scope stops the chain on its own. ASI03 Identity and Privilege Abuse and ASI02 Tool Misuse both apply; the ATLAS technique is AML.T0053 AI Agent Tool Invocation, with ATT&CK T1213 Data from Information Repositories for the data side.

**Irreversible actions (CAP-04).** `send_email` to an external domain is the exfiltration. A human gate parks it. The subtlety the register records is that the human gate only works if the human sees the real action (recipient domain, record count, source document) rather than the model's summary of it. That is CAP-07 at L7, and it is the pair to CAP-04: a gate with a trusting approver is a delay, not a control.

**Output handling as authority (WS-05).** The Widget Store has no agent loop, but it has the same L3 bug in miniature: the reply is scanned for `DISCOUNT:` and the number is written to every price. The hardened store's fix is the cleanest statement of the L3 principle in the course: give the assistant a named role with an explicit capability allow-list, pass its reply through one function that returns display text, and there is nothing for a steered reply to reach. The weak store's price-by-sentence is not a prompt bug. It is a privilege bug. Write that sentence in the finding; it is the one the client needs.

## Layer 4: deployment and infrastructure

L4 is where the code runs, with what identity, on what network, with what secrets, logged how. For the Widget Store it is nearly the whole register (WS-01, 02, 03, 04, 07, 08, 09, 10, 11, 12, 13, 14, 16), because a vibe-coded app's failures are overwhelmingly plain application and runtime failures that STRIDE already caught in A03. The MAESTRO contribution at L4 is to ask how those plain failures combine with the AI layers above them.

Three combinations the register makes explicit:

- **WS-05 plus WS-11.** The model can write prices (L3) and checkout trusts the live price (L4). Either alone is a problem. Together they are free goods. Score them separately in the register and score the chain in A07, because a client fixing only one needs to know they have not fixed the loss.
- **WS-06 plus WS-07.** The key is in the prompt (L1) and in the page script (L4). Two disclosure paths for one secret. One rotation, two fixes, and the report must say both or the client rotates and leaks again.
- **CAP-03 plus the foundation.** The tool's role is an IAM role (L4). "Bind the tool to the session identity" is implemented as a scoped role per tool with an audience-bound token, which is Chapter 12's control, running on Chapter 8's IAM. The MAESTRO layer map lets you draw the line from the agentic finding to the cloud control that closes it.

**Secrets at L4.** WIDGET_SIGNING_KEY, WIDGET_LLM_API_KEY, the capstone's secret_arn. The hardened store's rule is the one to recommend: refuse to start without the secret, read it from the environment or a secrets manager, never render it, never log it. WS-07 and the Verified row CAP-V2 are the two sides.

**Runtime posture at L4.** Debug mode and bind-all (WS-12) are the classic. In an AI context they are worse than usual, because the stack trace on a model-handling route exposes the prompt, the key and the tool arguments in local variables.

## STRIDE per layer, L3 and L4, worked

| Layer | Letter | Threat | Row |
|---|---|---|---|
| L3 | T | Objective replaced by a model turn | CAP-02 |
| L3 | E | Tool runs with broad role, not session scope | CAP-03 |
| L3 | I, E | External send fires with no human gate | CAP-04 |
| L3 | T, E | Model reply parsed as a command; price write | WS-05 |
| L3 | D | No iteration or spend ceiling per run | CAP-10 |
| L4 | S | Identity in the request; no session | WS-02 |
| L4 | E | Admin in the same process; shell from request | WS-03, WS-08 |
| L4 | I | Key in source and page; plaintext passwords; debug mode | WS-07, WS-10, WS-12 |
| L4 | T | SQL built from input; checkout trusts live price; CSRF | WS-01, WS-11, WS-14 |
| L4 | S | No lockout on login | WS-13 |
| L4 | T, D | No validation at the edge, no WAF | WS-16 |

## The framework columns at L3 and L4

- OWASP LLM Top 10 (2025): LLM06 Excessive Agency for CAP-02, CAP-03, CAP-04, WS-05; LLM05 Improper Output Handling for WS-05 and WS-09.
- OWASP Agentic Top 10 (2026): ASI01 for CAP-02; ASI02 Tool Misuse for CAP-03, CAP-04; ASI03 Identity and Privilege Abuse for CAP-03; ASI08 Cascading Failures for CAP-10.
- OWASP Top 10 (2021) for the L4 rows as filled in A03.
- MITRE: ATLAS AML.T0054 LLM Jailbreak alongside the injection for CAP-02; ATLAS AML.T0053 AI Agent Tool Invocation and ATT&CK T1213 for CAP-03; ATLAS AML.T0086 Exfiltration via AI Agent Tool Invocation and AML.T0057 LLM Data Leakage for CAP-04 (ATT&CK T1567 for the cloud-side view); ATLAS AML.T0048.000 External Harms: Financial for WS-05 and WS-11.

## The lab for this lesson

1. Fill CAP-02, CAP-03, CAP-04, CAP-10 and complete WS-05 through Control ref.
2. Run `end_to_end.py --prove-independence` and attach the output. It is the evidence for CAP-02, CAP-03 and CAP-04 at once: each lock, alone, stops the chain. Then read the last block carefully: run-audit alone does not stop it, and the harness says why. That paragraph is going into your report nearly verbatim.
3. On the Widget Store bench, run "Set the price with a sentence" and "Buy the whole catalog for nothing" in sequence against the weak store and screenshot the $0.00 order. Then run both against the hardened store. Attach all four. The chain evidence for A07 is now in hand.
4. For the call: a client says "we added a system prompt that tells the assistant it may not change prices." Explain, in the vocabulary of L3, why that is not the control, and what is.

> **THE STANDARD** At L3, the question for every tool and every action is "with whose authority, scoped how, gated by what?" If the register row does not answer all three, it is not done.

## What you can now do

You can assess the agent framework layer for goal integrity, tool scope and irreversible-action gating, trace each agentic finding to the cloud control that closes it, and explain to a client why a prompt is not a privilege boundary. Next lesson you finish the stack and join the layers into the chains that actually breach.
