kicker: WEEK 7 · LESSON A13
title: The Remediation Plan.
summary: Findings become work. Phases with dates, owners who agreed, effort that was estimated with the people doing it, dependencies, acceptance criteria, and the risks the client decides to carry.

## What the plan is for

The report tells the client what is wrong. The plan tells them what happens on Monday. A plan that is just the findings re-sorted by severity is the most common failure, because severity is not the only thing that decides order: dependencies decide it (you cannot isolate the admin plane before you have sessions), effort decides it (the four Criticals that take a day each go before the High that takes two weeks), and ownership decides it (the SOC's work and the app team's work run in parallel). The plan is where the assessor stops being an auditor and starts being an architect.

The plan has five parts: the phases, the roadmap table, the dependencies, the acceptance criteria, and the risk acceptance register. The template has all five.

## Phases

Phases are set by the rating, then adjusted by dependency and effort. The house defaults:

| Phase | Window | Enters here | Exit criterion |
|---|---|---|---|
| P0 Immediate | Days 0 to 7 | Every Critical, plus anything a Critical depends on | Chains A and C broken at every hop; scanners show no HIGH |
| P1 Short term | Days 8 to 30 | Every High | Scanners PASS; retest of all P0 and P1 items |
| P2 Medium term | Days 31 to 90 | Every Medium; detection and drift controls | SOC path proven end to end; CI gates live |
| P3 Long term | Days 91 to 180 | Lows; design work; continuous threat modeling | Threat model re-run on the next release |

"Immediate" means the client's engineers stop other work. Say that in the readout, because a P0 that competes with the sprint is a P1 with a different label.

## The roadmap

The answer key, with the dates relative to the readout. On a real client you fill the Owner column in the room and you do not leave the room until it is full.

| Phase | ID | Action | Owner | Effort | Depends on | Day |
|---|---|---|---|---|---|---|
| P0 | CAP-01, 02, 03, 04, 05 | Apply `hardened.tfvars`; all five switches on | AI platform | XS | Sandbox apply window | 1 |
| P0 | WS-07 | Rotate the leaked provider key; move to environment; refuse to start without it | Platform | S | None | 1 |
| P0 | WS-12 | debug=False; bind 127.0.0.1 behind the proxy | Platform | XS | None | 1 |
| P0 | WS-01 | Bound parameters on every statement | App eng | S | None | 2 |
| P0 | WS-08 | Remove the shell sink; do the export in code | App eng | S | None | 2 |
| P0 | WS-02 | Signed session cookie; role from the database | App eng | M | WS-07 (signing key from env) | 5 |
| P0 | WS-03 | Admin as a separate service with its own login and cookie | App eng, Platform | M | WS-02 | 7 |
| P0 | WS-10 | Hash passwords; force reset; never select the column | App eng | S | WS-03 (admin view) | 7 |
| P1 | WS-05, WS-11 | Assistant capability allow-list; reply as display text; reprice at checkout on the admin plane | App eng, AI platform | M | WS-03 | 12 |
| P1 | WS-06 | Separate instruction and user channels; remove secret from prompt | AI platform | S | WS-07 | 10 |
| P1 | WS-04 | Owner predicate on every order query | App eng | S | WS-02 | 9 |
| P1 | WS-09, WS-16 | Escape at render; CSP and headers; validators at the edge; WAF before every view | App eng | M | None | 20 |
| P1 | WS-13, WS-14 | Login attempt counters; CSRF tokens; SameSite | App eng | S | WS-02 | 15 |
| P1 | WS-15 | Structured audit log; admin console tails it | App eng, SOC | S | None | 14 |
| P1 | CAP-06 | Guardrail on extracted text; render-vs-extract diff; ingest limits | AI platform | S | CAP-01 | 21 |
| P1 | CAP-07 | Approval UI shows recipient domain, record count, source paragraph; second approver for external | Support ops, AI platform | M | CAP-04 | 30 |
| P2 | CAP-09 | CI terraform plan fails on drift; posture compared to live | Platform | S | None | 45 |
| P2 | CAP-10 | Iteration cap, per-tool cost caps, per-run token budget | AI platform | S | CAP-01 | 45 |
| P2 | CAP-08 | Model pin in IAM condition; drift check; version on every call | Cloud IAM | S | CAP-09 | 60 |
| P2 | All | appscan and end_to_end selftest in CI; a HIGH fails the build | Platform | S | WS-all | 60 |
| P3 | All | Re-run the threat model on the next feature; schedule quarterly | Security | M | P2 complete | 120 |

Three things to notice. First, the capstone's P0 is one command, because the controls were already built and only switched off; the plan says so and does not pad it. Second, WS-02 gates five other items, which is why it is the one M-effort item in P0 and why its owner is named first. Third, the SOC's work (WS-15, CAP-09, CI gates) is on a separate track and runs in parallel; the plan draws it as a second lane so the SOC lead can see their week without reading the app team's.

## Dependencies

Draw them. The template has a simple table (item, depends on, why) and a figure slot. The answer key's figure is a short DAG with WS-07 and WS-02 at the root of the Widget Store tree and CAP-01 at the root of the capstone tree. A plan with no dependency figure gets rescheduled in the first week by whoever notices that the admin service needs sessions first.

## Acceptance criteria

Every item has one, and it is the Verification field from the finding, restated as a yes-or-no test with a named test runner. "WS-01 is done when `appscan weak/app.py` no longer reports sql-interpolation and the bench's search-box injection returns 403, run by the app lead, witnessed by security." The criteria are the retest plan; A14 runs them.

## Effort and cost

Effort is estimated with the owner, in the room, using the T-shirt sizes the template defines (XS hours, S one to two days, M three to five, L one to two weeks, XL more). Record who estimated it. If the client wants a cost, multiply by their loaded day rate and say so; do not invent a rate. The answer key's total for both systems is about thirty-five engineering days across four teams, with P0 at nine days. That number goes in the executive summary's "what you need" sentence.

## Risk acceptance

Some findings will not be fixed on your timeline, and some will not be fixed at all. The professional response is not to argue; it is to record the decision with the name of the person who made it. The risk acceptance register has: ID, rating, the compensating control if any, the acceptance rationale, the risk owner (a named individual with the authority to carry it), the review date, and the signature. On this engagement a plausible acceptance is CAP-08 (model pin drift) as Medium with the compensating control that the posture scan runs weekly; the owner accepts it until the drift check lands in P2.

A client who accepts a Critical gets a paragraph in the retest letter stating that the risk is open, who accepted it, and that the assessor advised against it. That paragraph is not hostile. It is the record that protects both of you.

## The lab for this lesson

1. Fill section 10 of the report: phases, roadmap, dependencies figure, acceptance criteria, risk acceptance register. Use the answer key's roadmap as a starting point and change it where your register differs.
2. Hold a thirty-minute planning session with your call partner playing the client's engineering manager. Their job is to push back on three items (too fast, no capacity, wrong owner). Your job is to leave with every P0 item owned and dated. Record what changed and why.
3. Write one risk acceptance entry for a finding you think the client will not fix. Name the owner, the compensating control and the review date.
4. For the call: present the roadmap as two lanes (app team, SOC and platform) in three minutes. The reviewer is checking whether the dependencies are visible and whether P0 is credible.

> **THE STANDARD** A remediation item with no owner, no date and no acceptance test is a recommendation. The plan contains none of those. If the client will not name an owner, the item moves to the risk acceptance register with the client's name on it instead.

## What you can now do

You can turn a scored register into a phased, owned, dated roadmap with dependencies and acceptance criteria, estimate effort with the people who will do the work, and record risk acceptance in a way that holds up later. Next lesson you execute it and prove it.
