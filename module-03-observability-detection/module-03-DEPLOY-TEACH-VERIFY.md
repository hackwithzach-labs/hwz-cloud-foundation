# Module-03 — Observability & Detection :: DEPLOY · TEACH · VERIFY

**Chapter 10 · The SOC of the course.** Five phases, run in order, teardown always.
Every phase has three views telling one story: **terminal (CLI)** ⇆ **AWS Console (GUI)** ⇆ **Lab Console card at :5000**.

> Rebuilt 2026-08-07 from ch10 + the shipped module code (the original delivery
> never landed in the repo). This file lives in the module root and is the model
> runbook for modules 04–06.

---

## The one idea this module proves

Chapter 8 answered *"is the door locked?"* (posture, `hwz-scan`). This module answers
*"if someone walks through it anyway, will you ever know?"* (detection, `hwz-detect`).
A hardened account with no detection is a house with good locks and no alarm — and that
is precisely what you deploy first, on purpose. The whole SOC hangs off **one flag**:

| Profile | `detections_enabled` | State | Console verdict |
|---|---|---|---|
| `baseline.tfvars` | `false` | **BLIND** — hardened foundation, nothing watching | red card |
| `hardened.tfvars` | `true` | **WIRED** — full SOC on the same foundation | green card |

What the wired SOC is (teach this as three surfaces + one path):

1. **App layer** — CloudWatch metric filters on the app log group your Module-2 API
   writes to: `{ ($.status = 401) || ($.status = 403) }` (credential abuse) and
   `{ $.status = 429 }` (the cost cap firing). Each drives an alarm: 5+/min for
   401s ("one is a typo, five is someone trying"), first-hit for 429.
2. **Control plane** — EventBridge rules on CloudTrail management events. The trail
   delivers to S3 (for Athena history), *not* CloudWatch Logs, so you cannot
   metric-filter it — you match it on the default event bus instead. Three rules:
   `cloudtrail-tamper` (StopLogging/DeleteTrail/UpdateTrail — going blind is itself
   the loudest alarm), `sg-open-to-world`, `root-account-use`.
3. **Behavioral + posture** — GuardDuty (managed behavioral detection, findings routed
   to the alert path by a fourth EventBridge rule), AWS Config (recorder + 3 managed
   rules: public S3 read, root MFA, open SSH) and Security Hub (one prioritized view).

**One alert path:** every surface publishes to a single SNS topic
`hwz-lab-alerts`, with *your* email subscribed. An unconfirmed subscription is a
HIGH gap by design — an alert path that looks wired and delivers nothing is the
most dangerous kind.

---

## Before you start (every session)

```powershell
aws sso login                          # short-lived creds, nothing stored (rule 7)
aws sts get-caller-identity            # confirm: sandbox account, us-east-1 profile
```

Environment gotchas that already bit us — apply proactively:

- **Always** `terraform --% <args>` (the WinGet shim + PS 5.1 mangle flags otherwise).
- boto3 lives in the Module-2 venv:
  `C:\Users\hackwithzach\Claude-Cowork\PROJECTS\rebuild\module-01-cloud-foundation\module-02-api-security\.venv\Scripts\Activate.ps1`
- Env vars one per line: `$env:HWZ_PROFILE="baseline"` — never the bash inline form.
- Stale git lock → `Remove-Item .git\index.lock`.

Zero-cost warm-up (no AWS at all — proves the detector's logic before you trust it):

```powershell
cd C:\Users\hackwithzach\Claude-Cowork\PROJECTS\rebuild\module-01-cloud-foundation\module-03-observability-detection
python detect\detect.py --selftest
# selftest: blind fixture -> 9 gaps (expected > 0)
# selftest: wired fixture -> 0 gaps (expected 0)
# selftest: PASS
```

Teach it: `collect_live()` turns the account into a plain snapshot dict; `run_checks()`
judges the snapshot. Known-bad fixture must fail, known-good must pass — that is how
you trust any security tool before pointing it at something real.

**Cost note:** no NAT gateways, no idle compute. GuardDuty/Config bill by data
processed / configuration item — pennies at lab scale, and torn down in Phase 5.
Budget alarm assumed in place from Chapter 8 (alerts, not a hard stop).

---

## PHASE 1 — Deploy BLIND

**Concept before commands:** the foundation comes up pinned hardened (you proved those
controls in Ch8; re-weakening them teaches nothing). The detection layer deploys as
*nothing at all* — every resource in `modules/detection` is gated on
`count = detections_enabled ? 1 : 0`, so with the flag false there is no topic, no
filter, no rule, no GuardDuty, no Config, no Security Hub. Weak by policy, never
broken by omission.

```powershell
cd C:\Users\hackwithzach\Claude-Cowork\PROJECTS\rebuild\module-01-cloud-foundation\module-03-observability-detection\foundation
terraform --% init
terraform --% apply -var-file=baseline.tfvars -auto-approve
```

- `init` — downloads the AWS provider (~> 5.0), wires the two module sources
  (`../../module-01-cloud-foundation/foundation` + `./modules/detection`).
- `apply -var-file=baseline.tfvars` — expect **~42 adds, all of them foundation**
  (VPC, KMS, IAM, S3, Secrets, CloudTrail, observability — the Ch8 set), and
  **zero resources whose address starts with `module.detection`**. Scroll the
  plan and say that sentence out loud on camera — it is the whole point.

**Healthy result:** `Apply complete!` with no errors. KMS/CloudTrail can need a few
seconds of settling; a transient dependency error on first apply → re-run the apply.

---

## PHASE 2 — Prove you are blind (CLI + Console + attack)

### 2a. The detector says so

```powershell
cd ..
.\..\module-02-api-security\.venv\Scripts\Activate.ps1
python detect\detect.py --project hwz --region us-east-1
```

Expected: **`BLIND. 9 gap(s)`**, red LAB CONSOLE MAP banner, exit code 1.
The 9, in severity order — have the student explain each in one sentence:

| # | Sev | Surface | Gap |
|---|---|---|---|
| 1 | HIGH | cw-filter | `unauthorized-access` — 401/403 floods pass unseen |
| 2 | HIGH | cw-filter | `cost-cap-breach` — LLM10 pressure triggers no alarm |
| 3 | HIGH | eventbridge | `cloudtrail-tamper` — blinding the trail is unaudited |
| 4 | HIGH | sns | no alert topic — findings have nowhere to go |
| 5 | HIGH | guardduty | off — no behavioral baseline |
| 6 | MED | eventbridge | `sg-open-to-world` — re-opened door, no alert |
| 7 | MED | eventbridge | `root-account-use` — root used, nobody paged |
| 8 | MED | config | not recording — no posture history, no drift |
| 9 | MED | sec-hub | off — findings scattered across consoles |

*(The 10th check, CloudTrail→S3 for Athena, PASSES even while blind — the hardened
foundation is already delivering. Detection is missing; evidence is not. That contrast
is the chapter.)*

### 2b. See the absence with your own eyes (Console, us-east-1 — 8 screens)

Tool output is evidence; the interface is recognition. Weak-state walk:

1. **CloudWatch → Logs → Log groups → the `hwz-lab` app log group → Metric filters
   tab** → "There are no metric filters." The log is *right there*, full of data,
   and nothing reads it.
2. **CloudWatch → Alarms** → no `hwz-lab-*` alarms.
3. **EventBridge → Rules (default bus)** → no `hwz-lab-*` rules.
4. **SNS → Topics** → no `hwz-lab-alerts`.
5. **GuardDuty** → the *welcome/enable* marketing page. That page IS the finding.
6. **Config** → "Set up AWS Config" — not recording.
7. **Security Hub** → the enable page.
8. **CloudTrail → Trails** → the foundation trail, logging ON, delivering to S3 —
   the one detection-adjacent thing that already exists, and it is history, not alerting.

Screenshot each — they are the "before" half of every before/after pair in the book,
the course site, and the YouTube b-roll.

### 2c. Attack the blind account and read the silence (as in ch10)

Run the Module-2 harness against the API (local, free), then open the app log group:
a wall of 401s, the 429 where the cap held, CloudTrail recording every management
call — everything logged, nothing told you. This is the first of the two log reviews.
Median real-world dwell time is measured in hundreds of hours, and every one of those
hours is an account exactly like this one.

Lab Console (:5000): the **Observability & Detection** card, red, "BLIND" — same
story the terminal just told.

---

## PHASE 3 — Harden: flip the flag, read the diff first

**Plan before apply — the diff IS the SOC.** One flag and an email change; every
filter, alarm, rule, detector, recorder, and the hub appear at once.

```powershell
cd foundation
terraform --% plan -var-file=hardened.tfvars -var alert_email=zach@hackwithzach.com
```

Read it out loud: **~25–30 adds, every address starting `module.detection.`** —
topic + policy + subscription, 2 metric filters, 2 alarms, 4 EventBridge rules
(3 control-plane + 1 GuardDuty-findings) + 4 targets, GuardDuty detector, the Config
set (bucket, role, recorder, channel, 3 rules), Security Hub, the SOC dashboard.
Zero changes under `module.foundation` — hardened stays hardened.

```powershell
terraform --% apply -var-file=hardened.tfvars -var alert_email=zach@hackwithzach.com -auto-approve
```

**Then immediately: open the inbox and click the SNS confirmation link.**
Until you do, `hwz-detect` keeps reporting a HIGH gap — on purpose.

---

## PHASE 4 — Verify WIRED (CLI + Console + re-attack)

### 4a. The detector agrees

```powershell
cd ..
python detect\detect.py --project hwz --region us-east-1
# PASS. Detection is wired. If it happens, you will see it.
```

Green LAB CONSOLE MAP banner, exit 0. Flip the Lab Console card: green, "WIRED".

### 4b. The same 8 screens, present tense

Walk the same console paths from 2b and narrate what changed on screen: two metric
filters on the log group; two OK alarms; four enabled rules each targeting
`hwz-lab-alerts`; the topic with one **Confirmed** subscription; GuardDuty showing a
detector (Findings empty — healthy); Config recording with 3 rules evaluating;
Security Hub aggregating; plus the `hwz-lab-soc` dashboard with both metrics graphed.

### 4c. Same attack, different ending

Re-run the harness. Within minutes: the unauthorized-access alarm goes ALARM and
emails you; the cost-cap alarm fires on the first 429; GuardDuty/Security Hub begin
their baseline. Second log review: evidence + an alert is detection; evidence alone
is an autopsy. *(Optional console demo: stop/start the trail once to watch
`cloudtrail-tamper` page you — the act of going blind is itself the loudest alarm.)*

---

## PHASE 5 — Teardown (non-negotiable)

```powershell
cd foundation
terraform --% destroy -var-file=hardened.tfvars -var alert_email=zach@hackwithzach.com -auto-approve
```

Expect foundation + detection destroyed together (~70 resources). Then the console
sweep: CloudWatch (no groups/alarms/dashboard), EventBridge (no rules), SNS (no
topic), GuardDuty/Config/Security Hub back to their enable pages, S3 (no `hwz-lab-*`
buckets — Config bucket has `force_destroy = true`), EC2 (no stray ENIs).
Note actual cost after 24h for the chapter's cost claims.

Known snags: Security Hub sometimes needs a second destroy pass if findings arrived
during the session; SNS pending-confirmation subscriptions can't be deleted by API —
they expire on their own after 3 days (cost: zero).

---

## What the student can now say

Posture is not detection. An account can pass every scan and still be blind. I can
watch an app log with metric filters, watch the control plane with EventBridge
because the trail delivers to S3 not CloudWatch, turn on the managed layer, funnel
everything to one confirmed alert path, and prove the whole thing with a detector
that splits collection from judgment and self-tests against known-bad and known-good.
Attack in silence, wire the SOC, attack again, get the page.

Build it. Release it. Break it. Harden it.

© 2026 Vigilantia Technologies INC. All rights reserved.
