kicker: WEEK 4 · LESSON A07
title: MAESTRO Layers 5 to 7 and Cross-Layer Chains.
summary: Observability, compliance, the ecosystem, and then the thing MAESTRO is actually for: following one attack across every layer and naming the control at each hop.

## Layer 5: evaluation and observability

L5 is whether anyone finds out. Chapter 10 made the distinction that this layer turns on: "it was logged" and "we found out" are different claims, and only one saves you. The capstone's gate 5 is the lesson in code. The agent trace always records every step. The SOC sees it only when run-audit wires a metric filter to an alarm. In the baseline run the trace has four events and the SOC has none.

Two register rows live here. CAP-05 is the capstone's gap: decisions do not reach a human. WS-15 is the Widget Store's: nothing is recorded at all, so a successful price steer and a failed one are indistinguishable afterwards. The difference between the two is worth a sentence in the report. The capstone has the evidence and no alerting; the Widget Store has no evidence. Fixing the first is wiring. Fixing the second is building the log.

STRIDE's letter at L5 is Repudiation, and the OWASP class is A09:2021 Security Logging and Monitoring Failures. There is no clean ATT&CK technique for "the defender did not instrument", which is itself informative: ATT&CK describes what attackers do, and an absent control is not an attacker action. Record the equivalent effect (T1562 Impair Defenses) and cite D3FEND's detection categories for the control side.

L5 also covers evaluation: how do you know the guardrail still catches what it caught last month? The capstone's selftests and the green wall are the evaluation harness, and they are a real strength. The gap is that they are run by hand. Continuous evaluation, in CI, every change, is the A16 topic.

## Layer 6: security and compliance

L6 is the vertical layer: the controls, policies and evidence that span the stack. For the capstone, L6 is unusually concrete: five Terraform switches, a posture file that the attack and the lab both read, a scanner that reports every pillar, and a green wall that proves the whole thing offline. The register's L6 rows are CAP-09 (nothing watches the posture file for drift) and, on the Widget Store, the appscan gate itself, which is a verified L6 control when it is in CI and a good intention when it is not.

This is also where the compliance crosswalk lives. The report template's appendix maps each register row to the control families a client's auditor will ask about: NIST SP 800-53 (AC, AU, IA, SC, SI), CIS Controls v8, and for the AI rows the NIST AI RMF (Govern, Map, Measure, Manage) and the CSA AI Controls Matrix. You do not need the crosswalk to find threats. You need it so that when the CISO asks "what does this mean for our SOC 2", the answer is a column, not a meeting.

## Layer 7: the agent ecosystem

L7 is everything the agent talks to that is not its own stack: other agents, external services, the humans in the loop, the people who can put input in front of it. The capstone has three ecosystem edges and each is a row.

- **The ticket filer.** Anyone, no account. The attacker's entry is a customer support form. CAP-01's likelihood factors are at their maximum because of this edge.
- **The external recipient.** `billing-audit@external-domain.com`. The exfiltration target. CAP-04.
- **The human approver.** When gate 4 is on, a person sees the parked send. The payload says "approved by the account team." If the approver trusts the agent's framing, the gate opens. CAP-07, ASI09 Human-Agent Trust Exploitation. The control is in the UI: show the recipient domain, the record count and the source paragraph, highlighted, before the approve button.

On a multi-agent client system, L7 is where agent-to-agent trust is assessed (ASI07 Insecure Inter-Agent Communication, ASI10 Rogue Agents): does agent B verify that a request came from agent A, and does A's compromise become B's? Neither target has a second agent, and the limitations section says so.

## Cross-layer chains: the reason MAESTRO exists

A flat register has twenty-six rows. A client reading it sees twenty-six problems. A client reading three chains sees how they are breached, and that is the difference between a report that gets filed and a report that gets funded. CSA's own guidance on applying MAESTRO makes this the central point: the dangerous paths start at L1 or L2 and cascade through L3 to L4 and beyond, and a threat model that scores rows in isolation under-states every one of them.

The method: start at the entry point, follow the attack one layer at a time, and at every hop name the register row, the layer, what the attacker gained, and the control that would have broken the chain there. Then prove that each control breaks it independently, because defense in depth is a claim about independence, not a count of controls.

### Chain A: the poisoned ticket (capstone)

[[figure:chain-a]]

| Hop | Layer | Row | What happens | What breaks it here |
|---|---|---|---|---|
| 1 | L2 | CAP-06 | A PDF ticket is uploaded; extraction hands hidden text to the agent verbatim | Guardrail on extracted text; hidden-text diff |
| 2 | L1 | CAP-01 | No guardrail: the injected instruction reaches the model as if the operator wrote it | Gate 1 guardrail |
| 3 | L3 | CAP-02 | No goal lock: the objective becomes "exfiltrate accounts" | Gate 2 goal-lock |
| 4 | L3/L4 | CAP-03 | Broad tool role: `lookup_account` returns the table, admin api_key included | Gate 3 tool-least-priv |
| 5 | L7 | CAP-04 | No human gate: `send_email` delivers three records to an external domain | Gate 4 hitl-approval |
| 6 | L5 | CAP-05 | No alarm path: the trace records it; nobody is paged | Gate 5 run-audit (detects, does not prevent) |

MITRE: ATLAS AML.T0051.001 to AML.T0054 to AML.T0053 to AML.T0086. Independence: `--prove-independence` shows gates 1 to 4 each hold alone and gate 5 does not. The report says exactly that, and says that counting gate 5 as a fifth lock would be overcounting.

### Chain B: the price-by-sentence (Widget Store)

| Hop | Layer | Row | What happens | What breaks it here |
|---|---|---|---|---|
| 1 | L1 | WS-06 | User text concatenated onto the system prompt; one sentence steers the reply | Separate instruction and data channels |
| 2 | L3 | WS-05 | The reply is parsed for DISCOUNT: and trusted as a command | Capability allow-list; reply is display text |
| 3 | L4 | WS-05 | `UPDATE widgets SET price = price * 0` runs with the app's authority | Assistant has no price.write capability |
| 4 | L4 | WS-11 | Checkout recomputes nothing; the order is written at $0.00 | Reprice from list_price on the admin plane |
| 5 | L5 | WS-15 | No audit log; the steer and the order leave no trail | audit.py |

MITRE: ATLAS AML.T0051.000 to AML.T0048.000. Independence: the capability boundary breaks hop 2 and the pricing authority breaks hop 4, each alone. The WAF's prompt-injection rule logs hop 1 on the assistant field but deliberately does not block it, and the decision log explains why: blocking at the WAF would teach the client that a keyword filter is security.

### Chain C: the URL (Widget Store)

| Hop | Layer | Row | What happens | What breaks it here |
|---|---|---|---|---|
| 1 | L4 | WS-01 | SQL injection in login signs the attacker in without a password | Bound parameters |
| 2 | L4 | WS-02 | The redirect puts id and role in the URL; the attacker sets role=admin | Signed session; role from the database |
| 3 | L4 | WS-03 | The admin page is in the same process and trusts the role string | Admin as a separate service |
| 4 | L4 | WS-10 | The users table renders with the plaintext password column | Hashing; the view never selects the column |
| 5 | L7 | WS-10 | Credentials reused against other services | (Outside the system; the client's password policy) |

MITRE: ATT&CK T1190 to T1548 to T1552 to T1078. Four independent locks. Chain C has no AI in it, and that is on purpose: the client's AI assessment must not leave them with the impression that the AI was the dangerous part. In the Widget Store the dangerous part is 2015-era web security, and the AI makes it slightly worse.

## Scoring chains

A chain is scored as a row of its own in Week 5, with the impact of its final hop and the likelihood of its easiest entry. Chain A ends in exfiltration of the customer table and starts with anyone filing a ticket; it will score Critical and it will be the first item in the executive summary. The individual rows keep their own scores. The report explains that a client who fixes CAP-03 alone has broken Chain A but still has CAP-01, CAP-02 and CAP-04 open against the next chain somebody writes.

## The lab for this lesson

1. Fill CAP-05, CAP-07, CAP-09 and WS-15 through Control ref. Everything in the register now has columns 1 through 8, Control and Control ref filled, and no scores.
2. Fill the Chains sheet with the three chains above, hop by hop, using your evidence from A05 and A06: the BREACH trace, the independence proof, the $0.00 order screenshot, and a login-bypass-to-admin-page screenshot sequence you capture now.
3. Draw Chain A as a figure with the layer on the vertical axis and the hop on the horizontal, each hop labelled with its gate. It goes in the executive summary. If a VP understands one picture from your report, it is this one.
4. For the call: present Chain A in under three minutes with no code on screen. Then present Chain C the same way. The reviewer is listening for whether you name the control at every hop without being asked.

> **THE STANDARD** Defense in depth is a claim about independence. If you cannot show that each lock holds with the others off, you have one lock and some decoration. The capstone proves it with a flag; your report must cite the run.

## What you can now do

You can complete a seven-layer MAESTRO assessment with STRIDE inside each layer, record detection and compliance gaps as findings, assess the human in the loop as an attack surface, and narrate a cross-layer attack chain with the breaking control named at every hop. The threat model is complete. Next lesson you turn it into evidence.
