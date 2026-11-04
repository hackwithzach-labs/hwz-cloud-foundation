kicker: WEEK 1 · LESSON A01
title: The Engagement.
summary: What a threat model assessment is as a paid deliverable, how it is scoped, which frameworks do which job, and the rules you write before you touch a system.

## What you are being paid for

A client does not buy a threat model. They buy a decision. Specifically, they buy the ability to say, with evidence, which of the things that could go wrong with their system are worth money to prevent this quarter, which can wait, and which they will accept. Everything you produce in the next eight weeks exists to make that decision easy to make and easy to defend to an auditor, a board, or a regulator later.

That framing changes what good looks like. A threat model that lists forty threats with no scoring is unusable. A report that is technically perfect and buries the three things that matter on page thirty is unusable. A remediation plan with no owners is a list of good intentions. The engagement is only done when the client can act, and the measure of your work is whether they did.

There are three deliverables, and they are produced in this order because each one feeds the next:

1. **The threat model.** The system decomposed, the threats enumerated per element and per layer, each one scored. In the AI Threat Modeling System the threat model lives in the register workbook.
2. **The assessment report.** The threat model translated for people who make decisions, with findings written so they get acted on. The Word template.
3. **The remediation plan and retest.** The findings turned into a dated, owned roadmap, executed, and verified closed, with residual risk stated. The last two sections of the report plus the retest letter.

## Threat model, vulnerability assessment, penetration test

Clients mix these up, and the proposal you write has to be precise, because the price and the evidence standard differ.

| Engagement | Question it answers | Primary evidence | Where the AI Threat Modeling System sits |
|---|---|---|---|
| Threat model | What could go wrong with this design, and where? | Architecture, data flows, reasoning per element | Core: Weeks 1 to 4 |
| Vulnerability assessment | Which known weaknesses exist in this build? | Scanner output, configuration review | Supporting: appscan, scan.py, the green wall |
| Penetration test | Can an attacker actually get from here to there? | Exploitation, proof of impact | Supporting: the bench, end_to_end.py, the chains |
| Architecture review | Does the design meet a standard? | Control mapping, gap analysis | Supporting: Week 2 verified controls |

You are doing a threat model, and you are using the other three to turn threats into evidenced findings. That is the professional shape: the model tells you where to look, the scanner and the attack harness prove what you found, and the report says what it means. A threat model with no validation is a whiteboard. A pentest with no model is a list of whatever the tester happened to try.

## The framework stack

You will use seven frameworks. Each has one job. Using them for anything else is the most common way an assessment loses credibility with a senior reviewer, so learn the boundaries now.

| Framework | Job in this engagement | Not its job |
|---|---|---|
| STRIDE | Enumerate threats per element and data flow on the cloud, API and application tiers; and per layer inside MAESTRO | Scoring, prioritization |
| CSA MAESTRO | Decompose the AI system into seven layers; organize AI-specific threats by layer; trace cross-layer chains | Replacing STRIDE; it is a map, not an enumeration engine |
| OWASP Top 10 (2021), LLM Top 10 (2025), Agentic Top 10 (2026) | Name the class of weakness in a vocabulary the client's auditor already trusts | Completeness; a Top 10 is a floor |
| MITRE ATT&CK and ATLAS | Name the technique an attacker uses; tie each control to the step it breaks; tie each detection to the telemetry that sees it | Scoring |
| CVSS v4.0 | Technical severity of a vulnerability, in a form the client's ticketing and audit already understand | Design threats, business impact, priority |
| OWASP Risk Rating | Structured, defensible likelihood and impact factors for every threat, vulnerability or design flaw alike | A final verdict on its own |
| 5 x 5 likelihood and impact matrix | The one rating the executive summary reports and the roadmap is sorted by | Replacing the factors that justify it |

Two notes a reviewer will test you on. First, the OWASP Top 10 for web applications was renumbered in the 2025 edition. The course scanner and this register cite the 2021 identifiers because that is what most client ticketing, WAF rulesets and audit crosswalks still carry; the report template has a crosswalk note so a client on the 2025 numbering is not confused. Second, the OWASP Agentic Top 10 is labelled 2026 and was published in December 2025. Cite it by its label.

## Scoping statement

Scope is the first thing a client reads and the first thing a lawyer reads if anything goes wrong. Write it before any technical work and get it signed. For this engagement, yours reads like this; the report template has the fields.

**In scope.** System 1, Widget Store, weak build, all routes and the SQLite store, run on localhost ports 5200 (weak), 5201 and 5202 (hardened reference), 5115 (bench). System 2, Agentic support agent, baseline posture, the capstone Terraform root, the attack harness, the two MCP tools (`lookup_account`, `send_email`), the ingest path for .txt and .pdf tickets, and the five control switches. The Chapter 8 foundation and Chapter 9 API modules as composed by the capstone root, for verification of inherited controls.

**Out of scope.** The provider model itself (Bedrock, the Anthropic model) beyond the way the system calls it. The AWS control plane beyond what the composed Terraform configures. Physical, social engineering against staff, and denial of service against the lab host. The Lab Console as a product.

**Assumptions.** The weak builds represent what would have been deployed without review. The hardened builds are the client's own remediation candidates and are assessed as such, not as production. All testing is against systems the assessor owns, on localhost or in the assessor's own sandbox account, per the course disclaimer.

**Limitations.** The model call in the Widget Store is a stub; findings about prompt handling are assessed on the code around the call, which is where the controls live. The capstone's attack harness simulates the agent loop deterministically; the findings describe the control flow, which the Terraform switches govern in the real deployment.

Every one of those limitation sentences will reappear in the report. A reviewer who finds a limitation you did not declare assumes you did not know about it. Declare all of them.

## Rules of engagement

Even against your own lab, write them. The habit is the point, and the fields transfer directly to a real client.

- **Authorization.** Named system owner, named assessor, dates, written approval. Here: you, on your own systems, this week.
- **Testing windows.** When active testing may run. Lab: any time. Client: usually outside business hours for anything that can degrade service.
- **Allowed techniques.** Scanning, manual review, exploitation on the weak builds, no destructive payloads beyond the lab deny-list, no data exfiltration past the lab host.
- **Stop conditions.** What makes you halt and call the owner: discovering real customer data, discovering an active compromise, a control that would be degraded by your test.
- **Evidence handling.** Where screenshots, logs and command output are stored, who can see them, when they are destroyed. Findings contain credentials and secrets by nature; the evidence pack is itself sensitive.
- **Communication.** Who gets the critical findings immediately rather than in the report. On a real engagement, a Critical is phoned in the day it is confirmed, not held for the readout.

## The lab for this lesson

1. Copy the report template and fill in section 1 (Engagement overview), section 2 (Scope) and section 3 (Rules of engagement) for the two systems above. Use your own name, today's date, and the repository commit hash from `git rev-parse --short HEAD`.
2. Open the register workbook. Read the Frameworks sheet and the Scoring sheet without changing anything. You will be filling the Register sheet from Week 2.
3. Prove both targets are standing: run the green wall, run `appscan weak/app.py` and record the 21-gap count, run `end_to_end.py --selftest`. Paste the three outputs into the evidence folder as `00-baseline-*.txt`. These are the before pictures; without them the retest in Week 7 has nothing to compare against.

> **THE STANDARD** If the scope statement is not signed, the engagement has not started. On a real client, testing without a signed scope is the difference between a consultant and a defendant. Build the habit on the lab.

## What you can now do

You can explain the difference between a threat model, a vulnerability assessment and a penetration test to a buyer, and say which one they need. You can name the seven frameworks in this engagement and the one job each does. You can write a scope statement with assumptions and limitations that a reviewer cannot surprise you with. Next lesson you open the systems up.
