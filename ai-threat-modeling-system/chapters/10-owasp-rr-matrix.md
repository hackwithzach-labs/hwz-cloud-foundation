kicker: WEEK 5 · LESSON A10
title: Scoring, Part 2: OWASP Risk Rating and the Matrix.
summary: Every row, vulnerability or design threat or absent control, gets a likelihood, an impact, and a final rating that a non-technical reader can act on. The factors are what make it defensible.

## Why three scores and which one governs

Chapter 18 said risk is likelihood times impact and that the discipline is naming both. CVSS gives you a technical severity but hides the likelihood inside the exploitability metrics and says nothing about the business. The OWASP Risk Rating Methodology gives you sixteen named factors, eight for likelihood and eight for impact, each scored 0 to 9, averaged, and combined in a three-by-three table. The 5 x 5 matrix gives you the one word the executive summary carries.

The house method, which the methodology section of the report states in exactly these words:

1. **CVSS v4.0 base** is reported for every vulnerability as technical severity, for interchange with the client's tooling. It never sets the final rating.
2. **OWASP Risk Rating factors** are scored for every row, including design threats, absent controls and chains. The factor averages are the justification.
3. **The 5 x 5 matrix** rating is derived from the OWASP averages by a fixed mapping and is the final rating. It sorts the roadmap and leads the executive summary.
4. **Priority order** within a rating band is CVSS score descending, then crown-jewel rank from the asset register, then ID.

The mapping from a 0 to 9 average to a 1 to 5 axis is fixed and published in the workbook so the client can re-derive every rating: under 2 is 1; 2 to under 4 is 2; 4 to under 6 is 3; 6 to under 7.5 is 4; 7.5 and above is 5. The top band is deliberately narrow. A 5 on either axis means nearly every factor is at its worst, which is what Critical should cost. Matrix bands: 1 to 5 Low, 6 to 11 Medium, 12 to 19 High, 20 to 25 Critical. Critical needs a 4 x 5 or a 5 x 5. A 4 x 4 is High.

Why a fixed mapping rather than judgement at the last step: because the last step is the one the client reads, and if it is judgement, every rating is negotiable in the readout. If it is arithmetic on factors, the negotiation moves to the factors, where you have evidence.

## The likelihood factors

Threat agent factors, then vulnerability factors. Score each 0 to 9 using the OWASP anchor values; the workbook's Scoring sheet has the anchors as dropdowns.

| Factor | What you are estimating | Anchors |
|---|---|---|
| Skill level | How skilled is the attacker who could do this? | 1 security skills, 3 network and programming, 5 advanced user, 6 some technical, 9 no technical skills |
| Motive | How motivated are they? | 1 low or no reward, 4 possible reward, 9 high reward |
| Opportunity | What access do they need? | 0 full access or expensive resources, 4 special access, 7 some access, 9 no access needed |
| Size | How large is the group? | 2 developers or admins, 4 intranet users, 5 partners, 6 authenticated users, 9 anonymous internet |
| Ease of discovery | How easy to find? | 1 practically impossible, 3 difficult, 7 easy, 9 automated tools available |
| Ease of exploit | How easy to use once found? | 1 theoretical, 3 difficult, 5 easy, 9 automated tools available |
| Awareness | How well known? | 1 unknown, 4 hidden, 6 obvious, 9 public knowledge |
| Intrusion detection | Would it be noticed? | 1 active detection, 3 logged and reviewed, 8 logged without review, 9 not logged |

Two of these do most of the work on this engagement. **Size** is 9 for every Widget Store row and every capstone ingest row, because the attacker is anyone on the internet. **Intrusion detection** is 9 for every weak-build row, because nothing is logged. Those two alone push most averages past 7, and that is correct: a flaw that anyone can find and nobody would notice is as likely as flaws get.

## The impact factors

Technical impact, then business impact. The business factors are the ones to score with the client in the room, because you are guessing at their money and they are not.

| Factor | What you are estimating | Anchors |
|---|---|---|
| Loss of confidentiality | How much data, how sensitive? | 2 minimal non-sensitive, 6 minimal critical or extensive non-sensitive, 7 extensive critical, 9 all data |
| Loss of integrity | How much could be corrupted? | 1 minimal slightly corrupt, 3 minimal seriously, 5 extensive slightly, 7 extensive seriously, 9 all |
| Loss of availability | How much service, for how long? | 1 minimal secondary, 5 minimal primary or extensive secondary, 7 extensive primary, 9 all |
| Loss of accountability | Are the actions traceable? | 1 fully traceable, 7 possibly traceable, 9 completely anonymous |
| Financial damage | Cost to the business? | 1 less than the cost to fix, 3 minor effect on profit, 7 significant effect, 9 bankruptcy |
| Reputation damage | Harm to standing? | 1 minimal, 4 loss of major accounts, 5 loss of goodwill, 9 brand damage |
| Non-compliance | Regulatory exposure? | 2 minor violation, 5 clear violation, 7 high-profile violation |
| Privacy violation | How many people's data? | 3 one individual, 5 hundreds, 7 thousands, 9 millions |

**Loss of accountability** is the factor that makes the absent-control rows scoreable. CAP-05 and WS-15 are 9 on it, and that is the honest reason "no logging" lands High: not because logging failure is an exploit, but because every other finding becomes untraceable when it is missing.

## Three worked rows and a chain

**WS-01, SQL injection.** Likelihood 3, 9, 9, 9, 9, 9, 9, 9: average 8.25, HIGH, axis 5. Impact 9, 9, 5, 9, 7, 7, 7, 9: average 7.75, HIGH, axis 5. Matrix 25, **Critical**. OWASP overall Critical; CVSS 9.3 Critical. All three agree. Easy row.

**WS-12, debug mode on, bound to all interfaces.** Likelihood 5, 7, 9, 9, 7, 3, 6, 9: average 6.88, HIGH, axis 4. The 5 on skill and the 3 on ease of exploit are the Werkzeug debugger PIN; a reviewer who scores ease of exploit at 9 here has not tried it. Impact 9, 9, 7, 7, 7, 7, 5, 5: average 7.0, HIGH, axis 4. Matrix 16, **High**. OWASP overall Critical (both HIGH); CVSS 9.2 Critical. Here the three disagree, and the house rule is that the matrix governs. The report shows all three and explains: the matrix's narrow top band is doing its job; this is a serious finding that needs a PIN to become RCE, and the one that needs no PIN (WS-08) is the Critical.

**CAP-07, false authority claim aimed at the approver.** No CVSS. Likelihood 3, 9, 7, 9, 5, 5, 5, 7: average 6.25, axis 4. The 5s are honest uncertainty: the attack is easy to write and its success depends on a UI that does not exist yet. Impact 9, 3, 1, 7, 9, 9, 9, 9: average 7.0, axis 4. Matrix 16, **High**. A design threat with no reproduction lands High on its factors alone, which is the whole reason the factors exist.

**Chain A, the poisoned ticket.** Likelihood from the easiest entry (CAP-01): average 8.25, axis 5. Impact scored for the whole outcome, the customer table emailed to an external domain with no alarm: 9, 7, 1, 9, 9, 9, 9, 9, average 7.75, axis 5. Matrix 25, **Critical**. It is the first line of the executive summary. Chain C scores 20, Critical; Chain B scores 15, High, because the loss is financial and bounded by the catalog rather than regulatory and unbounded.

## The heat map

[[figure:heatmap]]

Every row and chain plotted on the 5 x 5. The report's executive summary carries this figure, and the first thing a reader sees is that the top-right cell has eight findings and two chains in it. That picture does what forty pages cannot.

## Priority order

With every row rated, sort: rating band descending, CVSS descending within the band, then crown-jewel rank, then ID. The register's Priority column is that sort, and the roadmap in A13 follows it. The answer key's top ten:

| # | ID | Rating | CVSS | Why it is here |
|---|---|---|---|---|
| 1 | CHAIN-A | Critical | n/a | The breach, end to end |
| 2 | CHAIN-C | Critical | n/a | Every password, from an unauthenticated form |
| 3 | WS-01 | Critical | 9.3 | Unauthenticated, automated, reads and writes |
| 4 | WS-02 | Critical | 9.3 | Any visitor is any user |
| 5 | WS-03 | Critical | 9.3 | And any user is admin |
| 6 | WS-08 | Critical | 9.3 | Unauthenticated RCE |
| 7 | CAP-01 | Critical | 9.3 | The entry hop of Chain A |
| 8 | CAP-02 | Critical | 9.3 | The hijack |
| 9 | CAP-03 | Critical | 9.2 | The table read |
| 10 | CAP-04 | Critical | 9.2 | The send |

## The lab for this lesson

1. Score every row's sixteen factors in the workbook. The sheet computes the averages, the OWASP levels, the axes and the matrix rating; it will not let you type a rating. For every factor you score above 7 or below 3, write the evidence file that supports it in the rationale cell.
2. Score the three chains the same way.
3. Compare to the answer key. For every row where your matrix rating differs from the key, find which factor moved it. Half the time it will be Intrusion detection or Loss of accountability, and the disagreement will be about whether "the hardened build has logging" counts when you are scoring the weak build. It does not: you score the system in front of you.
4. For the call: present the heat map in ninety seconds. Then defend WS-12 at High to a reviewer holding a CVSS of 9.2. If you can do that calmly, you can do a readout.

> **THE STANDARD** The final rating is arithmetic on factors you can evidence. If a rating changes in the readout, a factor changed and the register shows which one. Ratings never change because someone in the room preferred a different word.

## What you can now do

You can score any threat, vulnerability, absent control or attack chain on sixteen defensible factors, derive a final rating by a published mapping, reconcile it with CVSS without contradiction, and produce the heat map and the priority order that the rest of the report is built on. The threat model is finished. Next week you write the report.
