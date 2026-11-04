kicker: WEEK 2 · LESSON A03
title: STRIDE on the Application Tier.
summary: Walk every Widget Store element through the six letters, write the register rows, and learn the two habits that separate a usable STRIDE pass from a long list.

## The method, stated once

For each element on the diagram, and then for each numbered flow, ask the six questions from Chapter 7. Spoofing: can someone pretend to be a trusted identity here? Tampering: can data or config be altered here? Repudiation: can an action here be denied later? Information disclosure: can data leak here? Denial of service: can this be made unavailable? Elevation of privilege: can someone gain more than they should here?

Not every letter applies to every element. STRIDE per element is the standard refinement: external entities are mainly S and R; processes are all six; data stores are T, R, I and D; data flows are T, I and D. Use that to move fast and to notice when a letter that should apply has nothing under it, which is sometimes the real finding (a data store with no R entry usually means no audit log, which is WS-15).

Two habits that keep the pass professional:

**Write the threat, not the vulnerability.** "An attacker can sign in as any user by submitting a crafted username" is a threat. "SQL injection" is a vulnerability class. The register row carries both, but the threat sentence is what the client acts on and what you will score. Vulnerability classes go in the OWASP and CWE columns.

**One row per distinct threat, not per occurrence.** appscan reports sql-interpolation at four lines. That is one threat (the application builds SQL from input) with four locations, one row, locations in the evidence column. A register that has four rows for the same root cause inflates the count, which a reviewer reads as padding.

## The pass, element by element

What follows is the worked answer. Do the pass yourself first on the diagram from A02, then compare. The point of comparing is to find what you missed, and everybody misses something.

### Storefront process (all routes in one file)

| Letter | Threat | Row |
|---|---|---|
| S | The browser declares its own identity and role in the query string; any visitor is any user | WS-02 |
| S | No lockout or rate limit; credentials are printed on the login page | WS-13 |
| T | Queries built by string formatting let input change the statement | WS-01 |
| T | State-changing POSTs accept cross-origin submissions | WS-14 |
| R | No audit trail for login, state change, or model call | WS-15 |
| I | Debug mode shows source, paths and locals on any exception | WS-12 |
| I | Query exception text is returned to the page with the SQL | WS-01 (evidence) |
| D | No input validation; unbounded strings reach queries and templates | WS-16 |
| E | Admin console runs in the same process and trusts the role string | WS-03 |
| E | A request value reaches a shell | WS-08 |

### Assistant process

| Letter | Threat | Row |
|---|---|---|
| S | User text is concatenated onto the system prompt; the model cannot tell instruction from data | WS-06 |
| T | The reply is parsed for DISCOUNT: and written to prices; the model has write authority | WS-05 |
| I | The system prompt contains the provider key and can be extracted by asking | WS-06 |
| E | No capability boundary; the assistant runs with the application's full authority | WS-05 |

### store.db data store

| Letter | Threat | Row |
|---|---|---|
| T | Price column is writable from the model path | WS-05 |
| I | Password column is plaintext and selected by a view | WS-10 |
| I | Order rows fetched by id with no owner predicate | WS-04 |
| R | No audit of writes | WS-15 |

### CARTS data store

| Letter | Threat | Row |
|---|---|---|
| T, I | Keyed by the user id from the request; any customer reads or fills any cart | WS-02 (evidence) |

### Page template process

| Letter | Threat | Row |
|---|---|---|
| T | Review bodies and the model reply rendered unescaped; stored XSS runs for every visitor | WS-09 |
| I | The provider key is rendered into the page script | WS-07 |

### Checkout flow

| Letter | Threat | Row |
|---|---|---|
| T | Total computed from the live price at checkout, no server-side repricing, no payment step | WS-11 |

### Flow 5: request value to shell

| Letter | Threat | Row |
|---|---|---|
| E | Command injection via the export filename | WS-08 |

That is sixteen rows from twenty-one scanner gaps. The consolidation is deliberate and you should be able to explain every merge: secret-in-source and secret-to-client are one threat (the key is exposed) with two locations; no-waf, no-input-validation and no-security-headers are one defense-in-depth gap; no-audit-log and no-model-audit-log are one repudiation threat.

## Writing the register row

Open the workbook and fill one row per threat. The columns, in the order you fill them:

1. **ID.** WS-01 and up. Never renumber after the report is issued; IDs are how the client's tickets refer back to you.
2. **Title.** The threat in one sentence, as above.
3. **Component and DFD element.** File, function, and the element and flow number from your diagram.
4. **Trust boundary crossed.** From the numbered list in A02.
5. **MAESTRO layer.** For the Widget Store most rows are L4; the assistant rows are L1 and L3. Fill it even on a plain web app, because the report's layer summary needs it.
6. **STRIDE.** The letters, spelled out. Many threats carry two.
7. **OWASP, MITRE, CWE.** The vocabulary columns. OWASP Top 10 2021 for the web rows; LLM Top 10 2025 for the assistant rows; ATT&CK technique IDs for the web rows and ATLAS for the AI rows. CWE is what the client's SAST tool will report, so it closes the loop with their tooling.
8. **Evidence.** The appscan rule name and line numbers, plus the reproduction. You will complete this in A08; for now record the scanner reference.

Leave the scoring columns empty. Week 5 fills them with factors, and the factors are the reason the score is defensible. A score typed in Week 2 is a gut call.

## What the hardened store tells you

Every row above has a remediation reference in the hardened build, and you should fill the Control and Control ref columns now while the code is in front of you. The hardened store is unusual in that it ships with a decision log; read `DECISIONS.md` and cite the decision number in the Control ref column where one applies (WS-03 cites decision 4, WS-11 cites decision 5, WS-14 cites decision 11). A client who built their own hardening rarely has this. When they do not, your control column is the design you recommend, written in enough detail that an engineer can start.

## The lab for this lesson

1. Run the STRIDE pass on your own diagram before reading the worked tables. Write your rows. Then diff against the sixteen above and write one paragraph on what you missed and why.
2. Fill WS-01 through WS-16 in the Register sheet, columns 1 through 8 plus Control and Control ref. No scores.
3. Run `python3 appscan/appscan.py weak/app.py --table` and attach the output as evidence `WS-appscan-weak.txt`. Run it on `hardened/app.py` and `hardened/admin.py` and attach both PASS outputs. The pair is your first before-and-after.
4. For the Thursday call: pick the row you think is the most dangerous and the row you think is the most over-rated, and be ready to argue both. You will be scoring them in three weeks; find out now whether your instinct matches the method.

> **THE STANDARD** A STRIDE letter with nothing under it is a question, not a blank. "No Repudiation threats on store.db" is almost never true; it means you have not found the missing audit log yet.

## What you can now do

You can run STRIDE per element across a web application, consolidate scanner output into distinct threats, and write register rows with the vocabulary a client's auditor and tooling already use. Next lesson you do the same for the cloud and API tier, where most of the work is verifying what already holds.
