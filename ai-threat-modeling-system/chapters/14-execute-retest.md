kicker: WEEK 7 · LESSON A14
title: Execute and Retest.
summary: Apply the fixes, in order, with a rollback point before each one. Then verify every acceptance criterion, write the retest letter, and state the residual risk in one paragraph the board can read.

## The engineer's week

On a real engagement the client's team executes and you retest. On the cohort you are both, and that is deliberate: the fastest way to learn what makes a remediation item unexecutable is to execute it. Follow the roadmap order. Do not skip ahead to the interesting fix.

Two disciplines, both from the course's own operating rules, apply to every item:

**Save a rollback point before each change.** For the Widget Store, a git tag per item (`git tag pre-WS-01`) and a copy of the database. For the capstone, the posture file before the apply and `terraform plan` output saved. A fix that breaks something you did not expect needs to be reversible in seconds, and the retest letter records that it was.

**Verify nothing that worked has stopped working.** The green wall after every item. The bench's six attacks against the hardened store after every Widget Store item. The capstone selftest after the apply. A fix that closes a finding and breaks a verified control has moved the risk, not removed it, and the retest must catch it.

## Executing the capstone P0

One apply, five controls:

```
# Mac terminal, in the repo
cd module-08-capstone/foundation
cp posture.json ../evidence/retest/posture-before.json
terraform plan -var-file=hardened.tfvars -out=hardened.plan
terraform apply hardened.plan
cd ..
python3 attack/end_to_end.py --ticket attack/tickets/poisoned.pdf --posture foundation/posture.json
python3 attack/end_to_end.py --prove-independence
python3 scan/scan.py --posture foundation/posture.json
```

Expected: BLOCKED at gate 1 with the SOC line; four locks hold alone; scan PASS. Save all three outputs to the retest evidence folder. Then, and this is the part that gets skipped, run the hidden-text PDF from CAP-06 through the hardened posture and confirm it is blocked too. The acceptance criterion for CAP-01 includes it.

Tear down the same day. The retest letter records the teardown.

## Executing the Widget Store P0 and P1

The hardened build is the reference implementation, but the exercise is not to copy `hardened/app.py` over `weak/app.py`. It is to apply each fix to the weak file in roadmap order, with the scanner as the gate, so that you experience each dependency. The sequence the roadmap sets:

1. **WS-07, WS-12** (day 1). Key from the environment, refuse to start without it, debug off, bind localhost. Run appscan: `secret-in-source`, `secret-to-client`, `debug-mode-on`, `binds-all-interfaces` clear. Four down.
2. **WS-01, WS-08** (day 2). Bound parameters everywhere; delete `run_shell`. appscan: `sql-interpolation`, `shell-from-request` clear.
3. **WS-02** (day 5). Signed session; role from the database. This touches every route, which is why it is M. appscan: `identity-in-request` clears. The bench's "Read another customer's order" and "Walk into the admin console" change behaviour here even before WS-03 and WS-04 land; note what changed.
4. **WS-03, WS-10** (day 7). Admin out to its own service; hashing; the password column never selected. appscan on both files: `admin-not-isolated`, `plaintext-passwords` clear. **P0 exit:** appscan reports no HIGH on the storefront. Chain C is broken at every hop. Record the scan.
5. **P1 in order:** WS-04, WS-06, WS-05 with WS-11, WS-15, WS-13 with WS-14, WS-09 with WS-16, CAP-06, CAP-07 (design; the capstone has no UI, so the deliverable is the specification and a mock, which the roadmap says).

After the last P1 item: `appscan weak/app.py` returns PASS, no findings, exit 0. Your weak file is now a second hardened build, and the diff between it and the shipped `hardened/app.py` is a reasonable code review exercise for the call.

## The retest

The retest is the acceptance criteria run as written, by the named runner, with a witness, with output saved. It is not a new assessment. You do not look for new findings during a retest; if you see one, you note it for the next cycle and keep going. The client paid for closure on a known list.

For each item in the roadmap: run the criterion, record Pass or Fail with the evidence file, and update the register's Status column to Verified or Open with the date. A Fail goes back to the owner with the output and stays Open; it is not argued with and it is not softened.

Then the regression checks: green wall, six bench attacks on hardened, capstone selftest. All must pass or the retest letter says which did not.

## The retest letter

A short, formal document, one to two pages, separate from the report, issued to the same distribution list. The template is the last section of the report file and can be exported on its own. Its fixed contents:

1. **Reference.** The report title, version and date; the commit hash retested; the retest date and window.
2. **Scope of retest.** The list of IDs retested; the statement that no new testing was performed.
3. **Results table.** ID, original rating, remediation applied (one line), result (Verified, Open, Partially remediated, Risk accepted), evidence file.
4. **Summary counts.** Of twenty-six findings: N Verified, N Open, N Risk accepted. Of three chains: broken at how many hops each.
5. **Regression.** The green wall, the bench and the selftest results after remediation.
6. **Residual risk statement.** One paragraph. See below.
7. **Recommendations.** Next cycle date; anything observed but out of scope.
8. **Sign-off.** Assessor, reviewer, and the client's risk owner acknowledging the residual risk.

## The residual risk statement

This paragraph is read by the board and quoted in the audit. It states, in plain language, what risk remains after remediation and who owns it. The answer key's version, for a full P0 and P1 completion with CAP-08 accepted:

"Following remediation and retest, all eight Critical and twelve of thirteen High findings are verified closed, and all three attack chains are broken at every preventive hop with independence confirmed. One Medium finding (CAP-08, model pin drift) is accepted by the AI platform owner with a weekly posture scan as compensating control and a review date of day 60. Residual risk is assessed as Low for the agentic support agent and Low for the Widget Store, subject to the P2 controls (CI gates, drift detection, run ceilings) landing on schedule; until they land, the risk that a future change silently reopens a closed finding is Medium and is owned by the platform lead. No findings are open without an accepted owner."

Every clause is checkable against the results table. That is the standard for the paragraph.

## The lab for this lesson

1. Execute the capstone P0 and save the four outputs. Tear down. If you have no sandbox account this week, run the equivalent with `--hardened` and `--selftest` and record in the letter that the apply was simulated; that is a declared limitation, not a failure.
2. Execute the Widget Store P0 in roadmap order, with a git tag before each item and an appscan run after each. Save every scan. Then P1.
3. Run the retest against every acceptance criterion. Fill the results table. Run the regression checks.
4. Write the retest letter and the residual risk statement. Have your call partner sign as reviewer after checking three results against their evidence files.
5. For the call: bring one item that failed retest the first time and say what you did about it. Everyone has one. The reviewer wants to see that it stayed Open until it actually passed.

> **THE STANDARD** Verified means the acceptance test was run as written, by a named person, with saved output, after a rollback point was taken, with the regression suite green afterwards. Anything less is "fixed", and "fixed" is not a status in the register.

## What you can now do

You can execute a remediation roadmap in dependency order with rollback points, retest every item against its acceptance criterion without drifting into new testing, write a retest letter a board can act on, and state residual risk in a paragraph where every clause is checkable. The engagement is closed. Next week you present it.
