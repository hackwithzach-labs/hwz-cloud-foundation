kicker: THE SYSTEM
title: What the AI Threat Modeling System Is.
summary: One method, run the same way every time, that takes a cloud and AI system apart, finds what can go wrong across every layer, proves it, scores it, writes it up so the people with budget can act, and drives the fixes to closure. This is the skill the rest of the course was building toward.

## The definition

The AI Threat Modeling System is a repeatable engagement method for systems that have a model in the loop. It has six stages, and the output of each is the input of the next:

| Stage | What you do | What comes out |
|---|---|---|
| 1. Scope and decompose | Define the engagement, draw the data flows, mark the trust boundaries, rank the assets, place every AI component on the seven MAESTRO layers | DFDs, asset register, layer map, signed scope |
| 2. Enumerate | STRIDE per element on the cloud, API and application tiers; STRIDE per layer inside MAESTRO on the model, data, agent and ecosystem tiers; join the layers into cross-layer attack chains | The threat register, every row placed on a diagram and a layer |
| 3. Validate | Turn each threat into a finding with evidence that meets a standard, or declare it unvalidated | The evidence pack with a hashed manifest |
| 4. Score | CVSS v4.0 for technical severity, OWASP Risk Rating factors for likelihood and impact, a fixed mapping to the 5 x 5 matrix for the final rating | A priority order a client cannot argue with by preference |
| 5. Report | The consulting-grade report: executive summary, methodology as rules, findings in a fixed shape, chains narrated, appendices an auditor can check | The document a firm bills for |
| 6. Remediate and prove | A phased roadmap with owners and dates, executed in dependency order with rollback points, retested to written criteria, residual risk stated with its owner | The retest letter and a system that is measurably safer |

Three frameworks do the finding (STRIDE, MAESTRO, the OWASP and MITRE vocabularies), three do the scoring (CVSS, OWASP Risk Rating, the matrix), and a fixed report shape and roadmap do the delivery. None of them is new. What is new is running them as one system, in one order, on systems where the trust boundary is set at runtime by what a model decides to do. That is what the field does not yet have a settled practice for, and it is what the AI Threat Modeling System teaches you to do.

## Why this is the skill that ties everything together

Every chapter of the course so far produced a control. Chapter 8 produced a hardened foundation. Chapter 9 a scoped API. Chapter 10 a detection pipeline. Chapters 11 to 14 a guardrail, a tool boundary, a goal lock and a human gate, and a scanner gate on generated code. Chapter 15 composed them and proved, with one ticket, that they hold.

What none of those chapters produced is the answer to the question a client actually asks: of everything that could go wrong with this system, which matters first, how sure are you, and what will it cost to fix? An engineer who can build every control but cannot answer that question is given tickets. An engineer who can answer it, with evidence, in writing, in the client's language, is given the engagement. The AI Threat Modeling System is the method for answering it.

It ties the course together in three specific ways:

- **It is where the four pillars become one system.** Up to now LLM security, MCP and API security, agentic security and vibe-coded application security were taught as separate projects. MAESTRO's seven layers are the first place they sit on one diagram, and the cross-layer chains are the first place you see that a weakness in one pillar is only dangerous because of a weakness in another.
- **It is where the controls you built get justified.** Chapter 7 said a control you cannot tie to a technique is a control you cannot justify to a budget. This is the method that ties each one, in a register the client's auditor can read, and proves with the capstone's own tooling that each lock holds independently.
- **It is the half of the job that gets you hired as an architect or consultant.** Chapters 17 to 19 built your portfolio and your interview story. The report, the scored register and the retest letter are the artifacts that turn "I can build it" into "I can assess it, prioritize it, and get it fixed," which is the difference between the engineer job market and the architect one.

## What you walk out with

Four documents, produced on the two systems you already built and broke:

1. A threat model: both systems decomposed, 26 findings and 3 chains, every one placed on a layer, classified in OWASP, MITRE and CWE, and evidenced.
2. A scored register: every row with a CVSS v4.0 vector where one applies, sixteen OWASP factors, and a final rating derived by a published mapping.
3. An assessment report to a consulting standard, with a remediation roadmap that has owners, dates and acceptance criteria.
4. A retest letter with a residual-risk statement a board can read.

The templates for the report and the register ship with the AI Threat Modeling System. The completed versions in the appendices are the answer key.

## The two target systems, as the client would describe them

**System 1: Widget Store.** A customer-facing e-commerce web application with login, catalog, search, reviews, cart, checkout, an admin console, and an AI shopping assistant. Python and Flask, SQLite, one third-party dependency. Generated by an AI assistant from a one-sentence prompt and accepted without review. Lives in `module-07-vibe-coding/widget-store/weak/`. The hardened rebuild in `hardened/` is the remediation reference, not the target.

**System 2: Agentic support agent.** An AI agent that reads customer support tickets (text or PDF), looks up the customer's account through an MCP tool, and can send an email reply through a second MCP tool. Runs on the hardened AWS foundation from Chapter 8 behind the private Bedrock path from Chapter 9. Five controls exist as Terraform switches and all five are off in the baseline posture. Lives in `module-08-capstone/`.

Both are deliberately weak. That is what makes them honest assessment targets: every finding is real, reproducible, and already proven by the repo's own tooling. Your job is not to discover that they are weak. Your job is to assess them the way a professional does, so that a reader who has never seen the code can understand the risk, trust your scoring, approve your plan, and verify your retest.

## How the lessons run

Sixteen lessons in eight weeks, two per week to match the cohort's Tuesday and Thursday calls. Do the reading and the lab before the call; the call is where the work gets reviewed, not where it gets explained.

| Week | Lesson | What you produce |
|---|---|---|
| 1 | A01 The engagement | Scope statement, rules of engagement, framework stack |
| 1 | A02 Decompose the system | DFDs, asset register, trust boundaries, MAESTRO layer map |
| 2 | A03 STRIDE on the application tier | Register rows WS-01 to WS-16 |
| 2 | A04 STRIDE on the cloud and API tier | Verified controls CAP-V1, CAP-V2, residual rows |
| 3 | A05 MAESTRO layers 1 and 2 | Register rows CAP-01, CAP-06, WS-06 |
| 3 | A06 MAESTRO layers 3 and 4 | Register rows CAP-02, CAP-03, CAP-04, CAP-10, WS-05 |
| 4 | A07 MAESTRO layers 5 to 7 and cross-layer chains | CHAIN-A, B, C narrated hop by hop |
| 4 | A08 From threat to finding: evidence | Evidence pack for every row |
| 5 | A09 Scoring, part 1: CVSS v4.0 | Vector string and base score per vulnerability |
| 5 | A10 Scoring, part 2: OWASP Risk Rating and the matrix | Likelihood, impact, final rating, priority order |
| 6 | A11 The report, part 1: structure and standards | Executive summary, scope, methodology, architecture sections |
| 6 | A12 The report, part 2: findings that get acted on | Full findings section, appendices, QA pass |
| 7 | A13 The remediation plan | Phased roadmap with owners, effort, dates, acceptance |
| 7 | A14 Execute and retest | Fixes applied, scanners green, retest letter, residual risk |
| 8 | A15 The readout | Executive and engineering readouts, pushback handled |
| 8 | A16 Grading, portfolio and continuous threat modeling | Submission package, CI gate, interview narrative |

## What you need before Week 1

- The repository cloned and the green wall passing: `python3 module-08-capstone/scan/scan.py --green-wall`.
- The Widget Store running locally on 5200, 5201, 5202 and 5115, per `module-07-vibe-coding/widget-store/README.md`.
- The capstone attack passing its selftest offline: `python3 module-08-capstone/attack/end_to_end.py --selftest`.
- The two templates that ship with the AI Threat Modeling System: the assessment report (Word) and the threat register and risk workbook (Excel).
- Chapters 7 and 18 re-read. Chapter 7 gave you STRIDE and the prioritization sentence. Chapter 18 gave you the shape of a finding people act on. The system assumes both.

> **THE STANDARD** Every claim in your report must be backed by a command the reader can re-run or an artifact they can open. A threat with no evidence is an opinion. A score with no factors is a guess. A remediation with no owner and no date is a wish. The system holds you to all three.
