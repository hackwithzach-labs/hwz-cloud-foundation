kicker: WEEK 8 · LESSON A16
title: Grading, Portfolio, and Continuous Threat Modeling.
summary: What you submit, how it is graded, how it goes into the portfolio from Chapter 17, and how the threat model stops being a document and becomes a gate that runs on every change.

## The submission package

Six items, in one folder, at the top of your repository under `assessment/`:

| Item | Format | Graded on |
|---|---|---|
| Assessment report | The filled Word template, exported to PDF, version 1.0 with a named reviewer | Structure, executive summary, finding shape, QA list clean |
| Threat register and risk workbook | The filled Excel template | Every row evidenced; every rating derivable from factors; chains scored |
| Evidence pack and manifest | Folder plus manifest.txt with SHA-256 and commit hash | Completeness against the A08 manifest; handling rules followed |
| Remediation plan | Section 10 of the report, plus the dependency figure | Owners, dates, acceptance criteria, risk acceptance entries |
| Retest letter | One to two pages, exported separately, signed by the reviewer | Results table matches the register status; residual risk statement checkable |
| Readout recording | The twenty-minute executive readout | Decision asked for; no framework names; pushback handled |

## The rubric

Each item is marked against the standard its lesson set. The rubric is public so you can grade yourself before you submit, and your call partner grades you against the same sheet.

| Area | Weight | Pass | Distinction |
|---|---|---|---|
| Decomposition (A02) | 10 | DFDs with numbered boundaries; asset register; MAESTRO map | Every register row traceable to an element and a flow |
| Threat enumeration (A03 to A07) | 20 | All 26 rows and 3 chains present with STRIDE, layer, OWASP, MITRE, CWE | Consolidation explained; residual-risk rows present; STRIDE hand-off to MAESTRO explicit |
| Evidence (A08) | 15 | Pack complete to the manifest; threats-not-validated declared | Evidence of absence captured; weak-versus-hardened pairs for all six bench attacks |
| Scoring (A09, A10) | 15 | CVSS vectors defensible metric by metric; all factors scored; ratings derive by the mapping | Disagreements between CVSS, OWASP RR and the matrix explained in the report |
| Report (A11, A12) | 20 | All sections; findings in the fixed shape; QA list clean; reviewer signed | Three findings reproducible by a stranger from the report alone |
| Remediation and retest (A13, A14) | 15 | Roadmap owned and dated; retest letter with results table and residual risk | A failed retest item recorded honestly and closed on the second pass |
| Readout (A15) | 5 | Decision asked for; pushback answered from factors and evidence | Under twenty minutes with no unnecessary detail |

Seventy to pass. Eighty-five for distinction. The distinction column is what a senior reviewer at a consulting firm expects from a second-year consultant; if you hit it, say so in the interview.

## Into the portfolio

Chapter 17 built your portfolio around the monorepo, the before-and-after, the Lab Console and the capstone writeup. The assessment adds the artifact that the other four cannot supply: proof that you can do the consulting half of the job. Place it like this:

- **Top of the README**, one paragraph under the capstone writeup: "A full threat model and validation assessment of both systems, STRIDE and MAESTRO, scored on CVSS v4.0 and OWASP Risk Rating, with a remediation roadmap executed and retested. Report, register and retest letter in `assessment/`."
- **The heat map and the Chain A figure** as images in the README, next to the BREACH and BLOCKED screens. Four pictures, the whole story.
- **The report PDF** linked, with the classification changed to Public and the evidence pack removed; the pack stays private because it contains the lab's secrets and your own machine's paths.
- **The register workbook** linked, with the same redaction.

In the job search (Chapter 19), the assessment is the answer to the question "have you ever produced a client deliverable". For consulting, GRC and architecture roles it is often the deciding artifact, because most candidates have scanner output and no report.

## Continuous threat modeling

A threat model issued as a document is accurate on the day it is issued. The next feature changes the data flows, the next dependency changes the supply chain, and the next prompt change moves the trust boundary. The CSA's own work on operationalizing MAESTRO makes exactly this point: the useful form of the framework is not a document in a wiki but a classification that runs in the pipeline on every change. You already have most of the pieces.

**The gate you already have.** `appscan` exits non-zero on a HIGH. `end_to_end.py` exits 1 on a BREACH. `scan.py --green-wall` runs eleven proofs offline. Put all three in CI, on every pull request, and a change that reopens a finding fails the build before review. The roadmap's P2 item.

**Tag findings by layer.** Extend appscan's finding table with a MAESTRO layer per rule (secret-in-source is L4 with an L1 impact; llm-overprivileged is L3; no-audit-log is L5) and have it print the layer. Now a scan result is a layer map, and a new rule gets placed on the map when it is written. The homework from Chapter 14 (add one rule the scanner missed) becomes: add one rule, with its layer, its STRIDE letter and its OWASP ID.

**Re-run the model on triggers, not dates.** Quarterly is the floor. The real triggers are: a new tool added to the agent (L3 and L7 change), a new ingest source (L2 changes), a model or provider change (L1 changes), a new external integration (L7 changes), and any change to the five switches. Write the trigger list into the client's change process; the P3 roadmap item.

**Keep the register alive.** The workbook is the living document. New findings get new IDs; closed findings keep their rows with status Verified and the date; the retest letter is regenerated from the Status column. A register that is edited in place is an audit trail. One that is re-created each cycle is a new set of opinions.

**The minimum viable continuous model** for a client who has none: the register workbook, the three scanners in CI, and the trigger list in the change template. That is a week of work and it is the difference between a threat model that was done once and a security program.

## What the whole course now adds up to

You started this course at zero. You built a cloud foundation and proved it, built an API and a detection pipeline on it, built the four AI pillars and broke each one, composed them into a capstone and watched one ticket breach it and one apply stop it. Then, in the AI Threat Modeling System, you did the work that companies pay consultants for: you took those systems apart methodically, enumerated what could go wrong with a method that covers both the cloud and the AI, proved each threat with evidence, scored each one three ways so that no rating was a guess, wrote it up so that four different readers could act on it, planned the fixes with owners and dates, executed them with rollback points, retested them to a written criterion, stated the residual risk in a paragraph a board could read, and presented it for a decision.

That is the job. Not a part of the job; the job. Cloud and AI Security Engineer was the title. Architect and consultant is what you can now do, and the folder under `assessment/` is the proof.

## The lab for this lesson

1. Assemble the submission package. Grade yourself on the rubric. Fix anything under Pass.
2. Swap packages with your call partner and grade each other. Submit both grades with your package.
3. Put the three scanners in a CI workflow on your fork. Make one change that reopens WS-01 in a branch and confirm the build fails. Screenshot the red run and the green run. That pair goes in the README next to the heat map.
4. Add one appscan rule with its MAESTRO layer, STRIDE letter and OWASP ID, with a bad fixture and a benign fixture. That is the Chapter 14 homework, finished properly.
5. Write the trigger list for the two systems and add it to the repo's `SECURITY.md`.
6. For the final call: five minutes, the executive readout, timed, to the whole cohort. Then the question every interviewer asks and you can now answer: "Tell me about a time you found something serious and got it fixed."

> **THE STANDARD** A threat model is finished when it runs on every change without you. Until then it is a report, and reports age.

## What you can now do

You can deliver a complete threat model and validation assessment of a cloud and AI system to a professional standard, from scope to retest, and present it for a decision. You can place it in a portfolio where it does the work a resume cannot. And you can turn it from a document into a gate that runs in the pipeline, so the system stays assessed after you leave. Build it. Release it. Break it. Harden it. Assess it. Prove it holds.
