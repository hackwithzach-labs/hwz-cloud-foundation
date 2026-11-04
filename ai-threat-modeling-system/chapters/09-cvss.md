kicker: WEEK 5 · LESSON A09
title: Scoring, Part 1: CVSS v4.0.
summary: The common yardstick for technical severity. What it measures, what it does not, how to write a vector you can defend, and why every vulnerability in the register carries one even though it is never the final word.

## Why CVSS is in the stack

A client's ticketing system, their SLA with the vendor, their vulnerability management policy and their auditor's checklist all speak CVSS. If your finding says "Critical" with no vector, the client's security team has to re-score it to file it, and the number they pick will not be yours. If it says "CVSS:4.0 base 9.3 (Critical)" with the vector string, the finding drops straight into their process and keeps your severity. CVSS is in the stack because it is the interchange format, not because it is the best measure of risk. Chapter 7 said it: the common yardstick, and only the starting input.

The version is 4.0, published by FIRST in late 2023. Clients still on 3.1 exist; the workbook has a column for a 3.1 vector if a client asks, but you score in 4.0 and say so in the methodology.

## What CVSS v4.0 scores

The base score answers one question: how bad is this vulnerability, in the abstract, on the system it is in. Eleven base metrics in three groups.

**Exploitability.**

| Metric | Values | The question |
|---|---|---|
| Attack Vector (AV) | Network, Adjacent, Local, Physical | From how far away? |
| Attack Complexity (AC) | Low, High | Does the attacker have to defeat a security measure (ASLR, a race, a PIN)? |
| Attack Requirements (AT) | None, Present | Does the attack need a precondition the attacker does not control (a specific config, a race window)? |
| Privileges Required (PR) | None, Low, High | What account does the attacker need first? |
| User Interaction (UI) | None, Passive, Active | Does a victim have to do something? Passive is an ordinary action (viewing a page); Active is a deliberate one (approving a dialog). |

**Vulnerable system impact.** Confidentiality (VC), Integrity (VI), Availability (VA), each High, Low or None, on the system that has the vulnerability.

**Subsequent system impact.** SC, SI, SA, the same three on any other system the attack reaches. This is new in 4.0 and it replaces 3.1's Scope metric. It matters here because an AI system's vulnerability is often on one component and its impact on another: CAP-01's vulnerable system is the ingest path; its subsequent impact is the customer database and the external recipient.

**Not in the base score.** Threat metrics (Exploit Maturity) and Environmental metrics (how much this client cares about C, I and A; what they have changed) modify the base into CVSS-BT, CVSS-BE or CVSS-BTE. You report the base and, where you have the information, the environmental. The nomenclature matters: write "CVSS-B 9.3" so the reader knows which number they are looking at.

Severity bands: None 0.0; Low 0.1 to 3.9; Medium 4.0 to 6.9; High 7.0 to 8.9; Critical 9.0 to 10.0.

## Writing a vector you can defend

The rule: every metric value is a claim about the evidence, and you should be able to point at the evidence file that supports it. Three worked vectors from the register.

**WS-01, SQL injection in login and search.**
`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N` scores **9.3, Critical**.

AV:N because the login form is reachable over the network (WS-01-01). AC:L because no security measure has to be defeated; the payload works first time. AT:N: no precondition. PR:N: the login route is unauthenticated. UI:N. VC:H: the UNION query reads the users table including passwords (WS-01-02). VI:H: an injected statement can write (the login query is a SELECT, but the same construction pattern is used on the order INSERT). VA:L: a crafted query can degrade but the lab did not demonstrate an outage. SC/SI/SA:N: the impact stays on the storefront and its database; the subsequent credential reuse (Chain C hop 5) is outside the vulnerable system and is scored on the chain, not here.

**CAP-01, indirect prompt injection reaches the model.**
`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:N` scores **9.3, Critical**.

AV:N, AC:L, AT:N, PR:N: anyone can file a ticket. UI:N: no human has to do anything for the injection to reach the model; the agent processes the queue. VC:N and VI:H on the vulnerable system (the ingest and model path): the injection changes what the agent does, which is an integrity impact on that component, and it reads nothing by itself. SC:H and SI:H on the subsequent systems: the account store is read in full and an email is sent externally. This is the vector where 4.0's subsequent-system metrics earn their place; in 3.1 you would have been arguing about Scope:Changed.

**WS-09, stored XSS in reviews and the rendered model reply.**
`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N` scores **5.1, Medium**.

PR:L because posting a review requires a signed-in session (even if WS-02 makes that trivial, CVSS scores the vulnerability in front of you, not the chain). UI:P because a victim has to view the catalog, an ordinary action. VC:L and VI:L: session cookie theft and page defacement on the storefront. SC:L, SI:L: the stolen session reaches whatever the victim's account reaches.

Notice WS-09 is Medium in CVSS and High in the register's final rating (A10). That is not a contradiction. CVSS scored the vulnerability; the final rating adds that the victim population is every customer and the client has no detection. The report shows both numbers, and the methodology explains which one governs.

## Where CVSS stops

Six of the register's rows have no vector, and the report says why in each case:

- **Design threats** (CAP-07, the false authority claim). There is no vulnerability to score; there is a weakness in a control that does not yet exist.
- **Absent controls** (WS-15, WS-16, CAP-05, CAP-09, CAP-08). CVSS scores a vulnerability in a component. "There is no audit log" is not a vulnerability in a component; it is a missing component. Forcing a vector onto it produces a number nobody can defend.

A reviewer who sees a CVSS score on "no logging" marks the assessor as someone who scores by habit. Leave the cell empty, write "n/a: absent control, scored on factors" and move to A10, where every row gets a rating.

## The chain is not a CVSS vector

Chain A is Critical and it has no vector. CVSS scores one vulnerability; a chain is six. The temptation is to score the chain with the worst hop's vector and the final hop's impact. Resist it. The chain gets the matrix rating in A10, with its likelihood from the easiest entry and its impact from the final hop, and the report explains that this is why Chain A outranks every individual row.

## The lab for this lesson

1. Write a vector for every register row that is a vulnerability: WS-01 to WS-14, CAP-01 to CAP-04, CAP-06, CAP-10. Score them with the workbook's CVSS sheet (it computes the base score from the vector; do not type scores by hand) or with FIRST's calculator. For each metric value, note the evidence file that supports it in the CVSS rationale column.
2. Compare against the answer key. Where you differ, decide whether the difference is a judgement call (PR:L versus PR:N on WS-04 is arguable) or an error (AV:L on anything in a web app is an error). Write one paragraph on the judgement calls; those are the ones you will be asked about.
3. For the three rows where you think CVSS most under-states the real risk, write one sentence each on why. That sentence is the seed of the A10 likelihood and impact factors.
4. For the call: defend WS-09 at 5.1 to a reviewer who says stored XSS on every customer is obviously Critical. The correct answer involves the word "yet".

> **THE STANDARD** Every metric value points at an evidence file. A vector you cannot walk through metric by metric is a vector someone else will rewrite.

## What you can now do

You can write and defend a CVSS v4.0 base vector for a web or AI vulnerability, use the subsequent-system metrics correctly for an agentic chain, and say precisely where CVSS stops and why. Next lesson the rows that CVSS cannot score get scored, and every row gets its final rating.
