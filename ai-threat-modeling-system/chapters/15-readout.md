kicker: WEEK 8 · LESSON A15
title: The Readout.
summary: Two meetings, one set of facts. The executive readout that gets the decision, the engineering readout that gets the work started, and the pushback you will meet in both.

## Why the readout is a separate skill

Chapter 18 taught you to match the message to the room. The readout is where that gets tested live, with people who have budget and opinions and twenty minutes. A report that is perfect on paper and presented badly gets filed. A report presented well gets funded, and the person who presented it gets asked back. Consultants are rehired on readouts, not on reports.

You will give two. The executive readout is twenty minutes with the people who approve the plan. The engineering readout is sixty minutes with the people who execute it. Same facts; different first slide.

## The executive readout

Twenty minutes, five slides, the heat map and Chain A are two of them. Order:

1. **The picture.** The heat map. "Eight findings and two of the three attack chains sit in the top-right cell. Here is what that means."
2. **The chain.** Chain A as a figure, told as a story in ninety seconds with no technical terms: a ticket, a hidden paragraph, the agent believes it, the customer list leaves the building, nobody is told. Then one sentence: "Four separate switches each stop this on their own, and all four are currently off."
3. **The second chain.** Chain C, sixty seconds: a web form, no password needed, every customer's password on a screen.
4. **The ask.** The P0 phase: what, who, how many days. "Nine engineering days across two teams in the next week, and these three people as owners." Then the P1 and P2 shape in one sentence each.
5. **The decision.** What you need from this room: approval of the plan, the owners confirmed, a date for the retest readout, and a decision on the risk acceptance items.

What is not in the executive readout: framework names, CVSS, file paths, the register, the methodology. If asked, you answer in one sentence and offer the appendix. The reviewer on the cohort call will ask you a methodology question in the executive readout precisely to see whether you can decline the detail gracefully.

## The engineering readout

Sixty minutes, the engineers who own the items, the roadmap on screen for the whole hour. Order:

1. **The roadmap, both lanes.** Ten minutes. Walk P0 item by item with the dependency figure. Confirm each owner out loud.
2. **The Criticals, one by one.** Thirty minutes. For each: the reproduction live if it is safe and quick (WS-01's login bypass takes ten seconds and is worth doing), the fix with the reference implementation on screen, the acceptance test. Engineers believe a reproduction they watched; they argue with a screenshot.
3. **The chains.** Ten minutes. Chain A with the independence proof on screen. The point to land: fixing one hop is not fixing the chain, and the roadmap turns all four on because the next payload targets whichever is left.
4. **Questions and pushback.** Ten minutes, and expect it to run over.

## Pushback and what to say

Every readout has these. Have the answer ready, because the quality of your answer under pushback is what the room remembers.

**"This is a lab system, it was never going to production."** The weak build is what the model produced from the prompt the team would have used. Nothing in it was a mistake by a person; every gap is a default. The assessment is of what ships when a generated application is accepted without the control map. The hardened prompt is in the repo and it is one paragraph.

**"We have a WAF, that covers the injection findings."** The WAF is in the hardened build and the decision log says in writing that it is defense in depth, not the control. Bound parameters make WS-01 impossible with or without it. A WAF rule is a filter someone will eventually get past; a bound parameter has nothing to get past. Both are in the plan; only one closes the finding.

**"We told the assistant in its prompt that it cannot change prices."** An instruction to the model is not a privilege boundary. The model's reply still reaches a database write. WS-05 closes when the write path does not exist for the assistant, which is the capability allow-list, not the prompt. Show `guardrails.py`.

**"The guardrail catches the poisoned ticket, so the other three switches are extra."** `--prove-independence` on screen. Each holds alone. Gate 1 was the first lock the attack met; it is not the only one it needs, because the next ticket will be written to get past gate 1 and you want it to meet gate 2.

**"CVSS says 9.2 and you rated it High."** The rating is derived from sixteen factors in the register and the mapping is published. The factor that moves WS-12 is ease of exploit: the debugger needs a PIN. The item that needs no PIN, WS-08, is the Critical. Both are in P0 anyway. If the client prefers to track by CVSS internally, the column is there.

**"We cannot do P0 in seven days."** Then P0 is what can be done in seven days and the rest moves to the risk acceptance register with a named owner. The point of the register is that the decision is recorded with a name, not that the number is fixed. Offer the trade: which Critical stays open, and who signs for it.

**"Our auditor uses OWASP 2025, not 2021."** The crosswalk appendix has both. The 2025 edition renumbers (Injection moves to A05, Broken Access Control stays A01); the register's CWE column is stable across both and is what the scanner emits.

## Handling the room

Three habits:

- **Lead with the picture, not the count.** Twenty-six findings is a number people brace against. One picture of a ticket emailing the customer list is a thing people want to stop.
- **Never defend a rating by preference.** Every rating defence goes back to a factor and an evidence file. If a factor is wrong, change it in the room and let the rating follow; that is the method working, not failing.
- **Close with the decision.** The last thing said in the executive readout is the ask, repeated. The last thing in the engineering readout is the first item on Monday and who owns it.

## The interview version

Chapter 18 said the interview is a risk communication exercise in disguise. The readout is the rehearsal. When an interviewer asks you to walk through a project, you give the executive readout: the picture, the chain, the ask, the outcome. When they ask how you scored it, you give the methodology section in three sentences. When they ask what you would do differently, you give the item that failed retest and what you learned. That is a senior answer, and most candidates cannot give it because they have never closed an engagement.

## The lab for this lesson

1. Build the five executive slides. The heat map and Chain A figure come from the report; the other three are text. No slide has more than thirty words.
2. Give the executive readout to your call partner playing the CISO, in twenty minutes, timed. They ask two pushback questions from the list above and one you have not seen. Record it.
3. Give the engineering readout to the same partner playing the app lead, with the roadmap on screen. Reproduce WS-01 live.
4. Watch the recording of your executive readout. Write down every framework name, file path and number you said that did not need saying. Next time, say none of them.
5. For the call: the reviewer will pick one pushback line at random and you answer it cold.

> **THE STANDARD** The readout succeeds if the room leaves with a decision made, owners named and a date set. It fails if the room leaves impressed. Impressed is not a deliverable.

## What you can now do

You can present the same assessment to an executive room for a decision and to an engineering room for execution, handle the standard pushback without defending by preference, and turn a closed engagement into the interview answer most candidates do not have. One lesson left: packaging it and making it continuous.
