kicker: WEEK 6 · LESSON A11
title: The Report, Part 1: Structure and Standards.
summary: What a consulting-grade assessment report contains, in what order, held against the standards a senior reviewer actually applies. The template is the deliverable; this lesson is how to fill it so it survives review.

## Who reads it, in what order

A report has at least four readers and they read different pages. The executive reads page one and the heat map and stops. The engineering manager reads the roadmap and the findings' effort column. The engineer reads one finding at a time, reproduction and fix. The auditor reads the methodology, the scope, the crosswalk, and checks two findings against their evidence. A report that serves all four has a shape, and the shape is not negotiable. The template enforces it.

## The sections

| # | Section | Reader | What it must contain |
|---|---|---|---|
| 0 | Cover, document control, classification | All | Title, client, system, version, date, author, reviewer, distribution, classification (Confidential), change log |
| 1 | Executive summary | Executive | The decision in one page: overall risk, the top three things, the chain figure, the heat map, what you recommend, what you need |
| 2 | Engagement overview and scope | Auditor | In scope, out of scope, dates, team, commit hash, assumptions, limitations |
| 3 | Rules of engagement | Auditor | Authorization, windows, techniques, stop conditions, evidence handling |
| 4 | Methodology | Auditor, engineer | The framework stack and the one job each does; the scoring method stated as rules; the evidence standard; the validation ratio |
| 5 | Architecture and trust boundaries | Engineer | DFDs, numbered boundaries, asset register, MAESTRO layer map |
| 6 | Summary of findings | Manager | Counts by rating, by system, by layer; the priority table; verified controls |
| 7 | Attack chains | Executive, engineer | Each chain narrated hop by hop with the control at each hop and the independence evidence |
| 8 | Detailed findings | Engineer | One subsection per finding in priority order, in the fixed finding shape (A12) |
| 9 | Verified controls and residual risk | Auditor, manager | What held, how it was verified, what is left |
| 10 | Remediation roadmap | Manager | Phases, owners, effort, dates, dependencies, acceptance criteria (A13) |
| 11 | Retest and closure | All | Filled after A14: what was fixed, what was verified, residual risk statement |
| A | Threat register | Auditor | The workbook, exported |
| B | Evidence index | Auditor | The manifest with hashes |
| C | Framework crosswalk | Auditor | Register rows to OWASP, MITRE, CWE, NIST 800-53, CIS v8, NIST AI RMF |
| D | Glossary | Executive | Every term a non-specialist meets in sections 1 and 7 |

## The standards a reviewer holds you to

There is no single statute for assessment reports, but there is a set of published guidance that senior reviewers in consulting, GRC and penetration testing use as the bar, and the template is built to satisfy each. Know them by name; a client who asks "what standard is this report to" gets a list, not a shrug.

- **PTES (Penetration Testing Execution Standard), Reporting section.** The executive summary must stand alone; findings carry risk, evidence and remediation; the technical report follows the executive report, never the reverse.
- **OWASP Web Security Testing Guide, Reporting chapter.** Findings have a consistent structure; severity is justified; false positives are called out; the methodology is reproducible.
- **NIST SP 800-115, Technical Guide to Information Security Testing and Assessment.** Planning, execution and post-execution phases; the report documents the methodology, findings, and recommended mitigations; data handling and retention are defined.
- **NIST SP 800-30 Revision 1, Guide for Conducting Risk Assessments.** Risk is likelihood and impact; the register is the artifact; assumptions and constraints are explicit; the assessment is repeatable.
- **NIST SP 800-53 Revision 5.** The control vocabulary for the crosswalk (AC, AU, IA, SC, SI families).
- **ISO/IEC 27005.** Risk assessment within an ISMS; the terms "risk owner" and "risk acceptance" come from here and the roadmap uses them.
- **CIS Controls v8.** The second crosswalk column; the one most mid-market clients map to.
- **NIST AI RMF 1.0 and the Generative AI Profile (NIST AI 600-1).** The crosswalk for the AI rows: Govern, Map, Measure, Manage, and the GAI-specific risks (information integrity, confabulation, harmful bias is out of scope here, but data privacy and "human-AI configuration" are directly on CAP-07).
- **CSA MAESTRO and the CSA AI Controls Matrix.** The AI layer vocabulary and its control crosswalk.
- **Threat Modeling Manifesto.** Four questions: what are we working on, what can go wrong, what are we going to do about it, did we do a good job. Sections 5, 8, 10 and 11 answer them in that order; say so in the methodology.

You are not certifying compliance with any of these. You are saying that the report's structure, evidence standard and scoring method are consistent with them, which is what a reviewer wants to hear and what the methodology section states in one paragraph.

## The executive summary

Write it last, place it first, and keep it to one page plus the two figures. The order of sentences is fixed:

1. **What was assessed and when.** One sentence. "A threat model and validation assessment of the Widget Store web application and the agentic support agent, conducted against commit `abc1234` between dates."
2. **The overall picture.** One sentence with the numbers. "Twenty-six findings and three attack chains were identified: eight Critical, thirteen High, five Medium; two inherited cloud controls were verified."
3. **The three things that matter.** Chain A, Chain C, and the fact that neither system logs anything. Each in business language: "A customer support ticket containing one paragraph of hidden text causes the agent to email the full customer table to an outside address, and no alarm fires."
4. **What you recommend.** The P0 phase in one sentence: the five capstone switches on and the four Widget Store Criticals closed within seven days.
5. **What you need.** Owners named, a date for the readout, access for the retest.
6. **The figures.** Chain A as a picture; the heat map.

No framework names in the executive summary. No CVSS vectors. No file paths. The words STRIDE and MAESTRO appear for the first time in section 4.

## Methodology, as rules

The methodology section is where the auditor decides whether to trust the numbers, and it should read as rules rather than prose. The answer key's version is eleven numbered statements, and the first five are: (1) STRIDE per element on the application and cloud tiers, STRIDE per layer inside MAESTRO on the AI tiers; (2) every threat validated with the system's own tooling or by reproduction, or marked as unvalidated; (3) CVSS v4.0 base reported for every vulnerability as technical severity, never as the final rating; (4) OWASP Risk Rating factors scored for every row and chain, averaged per the methodology; (5) the final rating derived from the averages by the published mapping to the 5 x 5 matrix. The validation ratio, the limitations, and the commit hash close the section.

## Document control and classification

The cover carries a classification (Confidential: contains credentials, exploit detail and customer data references), a distribution list by name, a version number, a reviewer's name separate from the author's, and a change log. A report without a reviewer is a draft. On the cohort, your reviewer is your call partner; on a client, it is a senior who did not write it. The template has the table; fill it or the report is not issued.

## QA: what a reviewer rejects

Before the report goes anywhere, run it against this list. Each item is a real rejection reason from real reviews.

- The executive summary mentions a framework, a vector or a file path.
- A finding's rating cannot be re-derived from its factors in the register.
- A finding has no evidence file, or the file is missing from the manifest.
- Two findings describe the same root cause.
- A Critical finding has no owner in the roadmap.
- "Should", "could" or "may" appears where the evidence shows "does".
- An absent control carries a CVSS score.
- A limitation appears in a finding that was not declared in section 2.
- The scope says localhost and a screenshot shows a different host.
- The reviewer's name is the author's name.

## The lab for this lesson

1. Fill sections 0 through 7 of the report template. Sections 1 and 7 will be revised after A12; write them now anyway, because writing the executive summary is how you find out whether you understand your own findings.
2. Write the methodology as numbered rules. Eleven is the answer key's count; yours may differ, but every rule must be one you actually followed.
3. Run the QA list against what you have. Fix everything it catches. Note how many items it caught; that number should be zero by A12 and it is a useful measure of how far you have to go.
4. For the call: read your executive summary aloud in under two minutes to someone who has not seen the report. If they can tell you the three things that matter afterwards, it works.

> **THE STANDARD** The executive summary is the only page most of the people who pay for the report will read. If the decision is not on it, the report did not deliver the decision.

## What you can now do

You can structure an assessment report to serve four different readers, state the methodology as auditable rules, name the standards it is consistent with, and run the QA pass a senior reviewer runs. Next lesson you write the findings themselves.
