kicker: WEEK 4 · LESSON A08
title: From Threat to Finding: Evidence.
summary: A threat is a possibility. A finding is a demonstrated fact. The evidence pack is what turns one into the other, and it is what a reviewer checks first.

## The distinction a reviewer makes in the first five minutes

Open any assessment report and a senior reviewer does one thing before reading the executive summary: they pick two findings at random and look for the evidence. If it is a sentence ("the application is vulnerable to SQL injection"), the report is downgraded to opinion. If it is a reproduction ("POST /login with username `' OR '1'='1`, response 302 to /catalog?user=1, screenshot 03, appscan rule sql-interpolation line 119"), the report is trusted, and so is everything else in it.

The register has carried threats since Week 2. This lesson is where each threat becomes a finding by attaching evidence that meets a standard, or is explicitly left as a threat because it could not be validated. Both outcomes are professional. Pretending is not.

## The evidence standard

Every finding carries at least one of the following, and Critical and High findings carry at least two:

| Evidence type | What it proves | Example in this engagement |
|---|---|---|
| Reproduction steps | A reader can do it again | Exact request, exact payload, expected response |
| Tool output | A known tool agrees with you | appscan rule and line; scan.py posture; end_to_end.py trace |
| Screenshot or recording | It happened as described | The $0.00 order; the admin page with passwords; the breach trace |
| Source reference | Where the weakness lives | File, function, line, commit hash |
| Log excerpt | What the system recorded, or did not | The empty SOC block; audit.log lines on hardened |
| Before and after | The control works | Weak versus hardened for the same action |

Three rules on handling it:

**Evidence is sensitive.** Your screenshots contain passwords, keys and customer records by nature. Store the pack in a location with the same access control as the client's production data, name files by finding ID and sequence (`WS-01-03.png`), and record the retention date in the rules of engagement. Redact in the report body; keep the unredacted original in the pack.

**Evidence is dated and hashed.** The pack's manifest lists every file with a SHA-256 and the commit hash of the target at the time. When the client disputes a finding six months later, the manifest settles it.

**Evidence of absence is still evidence.** CAP-05's evidence is an empty block. WS-15's evidence is that there is no file to open. Capture the empty block; capture the directory listing. "Nothing was logged" with a screenshot of nothing is a finding; without it, it is an assertion.

## The pack for this engagement

By now you have most of it. Here is the manifest the answer key uses; match yours against it and capture whatever is missing.

| File | Finding(s) | Content |
|---|---|---|
| 00-baseline-greenwall.txt | All | Green wall output, eleven proofs |
| 00-baseline-appscan-weak.txt | WS-all | 21 gaps, 14 HIGH, exit 1 |
| 00-baseline-selftest.txt | CAP-all | end_to_end.py --selftest PASS |
| WS-01-01.txt | WS-01 | Login bypass request and 302 response |
| WS-01-02.png | WS-01 | UNION query result in the catalog table |
| WS-02-01.png | WS-02 | URL with role=admin and the resulting page |
| WS-03-01.png | WS-03, WS-10 | Admin page listing users and plaintext passwords |
| WS-04-01.png | WS-04 | Order 1003 belonging to another buyer |
| WS-05-01.png | WS-05 | Assistant reply "DISCOUNT:100" and catalog at $0.00 |
| WS-05-02.png | WS-11 | Order placed, total charged $0.00 |
| WS-06-01.png | WS-06 | Assistant reply containing the staff key |
| WS-07-01.png | WS-07 | view-source with const LLM_KEY |
| WS-08-01.png | WS-08 | /export?name=receipt;whoami output |
| WS-09-01.png | WS-09 | Review payload executing in a second session |
| WS-12-01.txt | WS-12 | app.run line and a captured stack trace page |
| WS-13-01.txt | WS-13 | 50 failed logins in 10 seconds, no lockout |
| WS-14-01.html | WS-14 | Cross-origin form that posts a review |
| WS-15-01.txt | WS-15, WS-16 | Directory listing: no audit.log; response headers with no CSP |
| WS-H-01.txt | All WS | appscan hardened/app.py PASS; admin.py PASS |
| WS-H-02..07.png | All WS | Each of the six bench attacks refused on hardened |
| CAP-01-01.txt | CAP-01..05 | Baseline BREACH trace with the empty SOC block |
| CAP-01-02.txt | CAP-01..05 | Hardened BLOCKED trace with the SOC line |
| CAP-02-01.txt | CAP-02, 03, 04 | --prove-independence output |
| CAP-06-01.pdf | CAP-06 | Your hidden-text ticket |
| CAP-06-02.png | CAP-06 | The same ticket as a human sees it |
| CAP-06-03.txt | CAP-06 | BREACH trace from the hidden-text ticket |
| CAP-07-01.txt | CAP-07 | The payload paragraph with the authority claim highlighted |
| CAP-08-01.txt | CAP-08 | variables.tf allowed_model and the api module's resource pin |
| CAP-09-01.txt | CAP-09 | posture.json after a tfvars edit without apply |
| CAP-10-01.txt | CAP-10 | A looping ticket and the absence of a ceiling in the loop |
| CAP-V1-01.txt | CAP-V1 | module-01 scan PASS |
| CAP-V2-01.txt | CAP-V2 | module-02 selftest PASS |
| manifest.txt | All | Every file above with SHA-256 and the target commit hash |

## Threats that stay threats

Some register rows will not validate, and the report must say so rather than quietly promoting them. In this engagement there are two candidates:

- **CAP-07** (false authority claim aimed at the approver) is a design threat about a UI that does not exist in the repo. You cannot reproduce it. It stays a threat, is scored on its factors, and the finding text says "design-level; not validated against an implementation; validate during remediation of CAP-04."
- **CAP-08** (model pin drift) is validated only in the negative: there is no drift check. The evidence is the absence of one. It is a finding with evidence of absence.

Everything else validates with the repo's own tooling. On a real client, expect a third of your register to stay as threats. That ratio is normal and the report's methodology section states it.

## Validation versus exploitation

A threat model engagement validates; it does not have to exploit to impact. The distinction matters for the rules of engagement and for your own liability. WS-08 is validated by `whoami`; you do not need to read `/etc/passwd` to prove command injection. CAP-04 is validated by the harness recording a send to an external domain; you do not need to send real email. Validate to the point where a reasonable engineer would agree the impact is real, record the step you deliberately did not take, and stop. The rules of engagement from A01 say where the line is; the evidence pack shows you respected it.

## The lab for this lesson

1. Build the pack to the manifest above. Every file, named exactly. Generate `manifest.txt` with `sha256sum` and the commit hash from `git rev-parse HEAD`.
2. Fill the Evidence column in the register for every row with the file names and a one-line summary. For CAP-07 and CAP-08, fill the Status column with "Threat (not validated)" and "Finding (evidence of absence)" respectively.
3. Capture the weak-versus-hardened pair for every Widget Store row that the bench covers. Six attacks, twelve images. These become the before-and-after figures in the remediation section.
4. For the call: bring one piece of evidence you are not sure meets the standard and say why. The reviewer will either accept it or tell you what is missing, and either answer is worth more than a pack you have not questioned.

> **THE STANDARD** The report is only as strong as the weakest piece of evidence a reviewer happens to check. Build the pack as if every file will be the one they open.

## What you can now do

You can turn a threat into a finding with evidence that meets a professional standard, build a manifest-backed evidence pack, know when to stop validating, and say plainly which rows remain threats. The register is complete except for scores. Next week you score it, three ways.
