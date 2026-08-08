# Cloud and AI Security Engineer — Course Recording Script

**HackWithZach · Zach Marcy** · one file, the whole course, in shooting order.

Every chapter below is written as a beat sheet: what to have open before you hit
record, the exact commands in order, the line that matters, and the screen that
sells it. Commands are verified against the repo as it actually stands, not as
it is supposed to stand.

**Read the status line on each chapter before you set up.** Four chapters can be
recorded today. Four cannot, and I have named exactly what is missing rather
than letting you find out with the camera rolling.

© 2026 Vigilantia Technologies INC. ™ HackWithZach.

---

## Recording status, honestly

| Ch | Module | CLI lab | Visual lab | Record today? |
|---|---|---|---|---|
| 8 | module-01-cloud-foundation | `scan/scan.py`, `fix/fix.py` | **missing** | CLI only |
| 9 | module-02-api-security | `app/`, `attack/attack.py` | **missing** | CLI only |
| 10 | module-03-observability-detection | `detect/detect.py`, `attack/emit.py` | `visual/` on 5110 | **Yes, complete** |
| 11 | module-04-llm-security | `scan/`, `attack/inject.py`, `guard/` | `prompt-injection-lab/` on 5111 | **Yes, complete** |
| 12 | module-05-ai-apis-mcp | `scan/`, `attack/toolattack.py` | **missing** | CLI only |
| 13 | module-06-agentic-ai | `scan/`, `attack/agentattack.py` | **missing** | CLI only |
| 14 | module-07-vibe-coding | **module does not exist** | **missing** | No |
| 15 | module-08-capstone | **module does not exist** | **missing** | No |
| 16 | hwz-lab-console | — | `hwz-lab-console/` on 5116 | Yes |
| 17–20 | career chapters | — | — | Yes, talk-to-camera |

**Shoot order I recommend:** 10, 11, 16 first. They are the two complete labs
plus the dashboard, they are your strongest material, and recording them proves
the format before you commit to eight more. Then 8 and 9 CLI-only. Then 12 and
13 once their visual labs land. Then 14 and 15 once the modules exist.

---

## The house format

Every lab chapter runs the same seven beats. Students learn the rhythm by
episode three and stop needing to be told what is happening.

1. **The claim** — one sentence of what most people get wrong.
2. **Deploy weak** — `terraform apply -var-file=baseline.tfvars`.
3. **Scan** — the scanner finds it, offline selftest first.
4. **Attack** — make the weakness real, on screen.
5. **Harden** — `terraform apply -var-file=hardened.tfvars`, read the diff.
6. **Prove** — rescan, same tool, opposite verdict.
7. **Count the cost and tear down** — every billable line, then destroy.

Beat 7 is not optional and it is not an afterthought. It is the beat that makes
students trust you with their AWS account.

### Standing pre-roll checklist

- Terminal at 110 columns, font large enough to read on a phone.
- `cd` to the module directory **before** you hit record. Nobody wants to watch
  you navigate.
- Browser at the right port, page already loaded, ready to refresh.
- `aws sts get-caller-identity` once, off camera, so you know the session is live.
- Say the region out loud the first time you show the console. Half of all
  "my resources are gone" is a wrong-region panic.

### The stop-parsing token

On Windows PowerShell, Terraform installed via WinGet needs `--%` or the flags
get mangled:

```powershell
terraform --% apply -var-file=baseline.tfvars
```

Show this once in Chapter 8 and reference it after. It saves you a hundred
support emails.

---

## Chapter 10 — Observability and Detection

**Status: complete, record this first.** Target 22–28 minutes.

### Pre-roll

```powershell
cd C:\Users\hackwithzach\Claude-Cowork\PROJECTS\rebuild\module-01-cloud-foundation\module-03-observability-detection
..\module-02-api-security\.venv\Scripts\Activate.ps1
```

Browser tabs: AWS Console on **us-east-1**, and `http://localhost:5110` loaded
but not yet scanned.

### Beat 1 — the claim (2 min, camera)

> "Chapter 8 hardened this account and I proved it with a scanner. Chapter 9
> put an API on it and I proved that too. And if someone breaks in tonight,
> nobody finds out. Posture is not detection. An account can pass every scan
> you own and still be completely blind, and that is the state most breaches
> sit in for months."

Then the promise: *by the end of this you will attack an account that cannot
see, wire the SOC, attack it again, and get the page.*

### Beat 2 — deploy blind

```powershell
cd foundation
terraform --% apply -var-file=baseline.tfvars
cd ..
```

Point at the outputs while they scroll: `alert_topic_arn = ""` and
`guardduty_detector_id = ""`. Say it plainly — **the detection layer is
provably absent, and I can point at the two empty strings that prove it.**

### Beat 3 — the offline selftest, then the scan

```powershell
python detect\detect.py --selftest
```

> "Before I point a security tool at a real account, I prove it against a
> known-bad case and a known-good case. Blind fixture, nine gaps. Wired
> fixture, zero. If it ever stops catching the bad one or starts complaining
> about the good one, I know before I spend a cent."

```powershell
python detect\detect.py --project hwz --region us-east-1
```

Nine gaps, five HIGH, red banner reading **BLIND**.

### Beat 4 — the silence, which is the heart of this chapter

Two things in that output say nothing, and they mean opposite things. This is
the best two minutes in the episode; do not rush it.

> "There is no finding for alarms. That is not because the alarms are fine.
> `check_alarms` loops over the metric filters it found, there are zero
> filters, so the loop never runs and it returns an empty list. That layer
> isn't healthy, it's **untested**. The absence of a finding is not evidence
> of a control — that is how audits get faked."

> "And there is no finding for CloudTrail either — but that one genuinely
> passed. The trail from Chapter 8 is still delivering to S3, composed
> underneath this module. I can hunt the past. I just can't see the present."

### Beat 5 — populate the logs, then read the silence

```powershell
python attack\emit.py --selftest
python attack\emit.py --dry-run
python attack\emit.py
```

> "Chapter 9's API runs on my laptop and logs to stderr. It never wrote to the
> cloud log group. If I open that group right now it's empty — and an empty
> log group is not evidence that nothing happened, it's evidence that nothing
> was ever delivered."

Then AWS Console → CloudWatch → Log groups → `/hwz-lab/app` → the new stream.
Show the 401s and the 429s. Then click the **Metric filters** tab: zero.

**The money shot of the whole chapter:** the populated log stream beside the
empty filter tab. Hold on it.

> "The evidence was always there. Nothing counted it. Nobody was paged."

### Beat 6 — the eight Console screens

Walk them in chain order, thirty to sixty seconds each: CloudWatch metric
filters, alarms, EventBridge rules, SNS topics, GuardDuty, Config, Security
Hub, CloudTrail. Seven absences and one control that is already correct.

> "Seven screens of nothing and one screen of something. That last one is
> inherited from Chapter 8, not rebuilt. That's the composition model, and
> it's also the honest picture of most real accounts: the recording is on,
> the watching is off."

### Beat 7 — the visual lab

Browser to `http://localhost:5110`, click **Scan my account**.

Read the cards as a chain, not as eight services: log line → number, number →
threshold, API call → event, event → a person.

Then stop on the amber Alarms card:

> "Amber. Not red, not green. **UNTESTED** — the scanner couldn't evaluate it,
> because nothing upstream exists. The first build of this screen rendered
> that card green and I caught it in a screenshot. A dashboard that can't tell
> you the difference between 'I checked and it's fine' and 'I couldn't check'
> is lying to you politely."

Then the integrity point, four lines of Python on screen:

> "This page makes no AWS calls and contains no detection logic. It imports
> the scanner I just ran and renders what it returns. One scanner, two
> renderings. The browser and the terminal cannot disagree, because there's
> only one thing to disagree with."

### Beat 8 — harden

Edit `hardened.tfvars`, set `alert_email` to a real address. Say out loud that
you are doing it.

```powershell
cd foundation
terraform --% plan -var-file=hardened.tfvars
```

> "Read the diff before you apply it. That diff **is** the SOC."

```powershell
terraform --% apply -var-file=hardened.tfvars
cd ..
```

Go confirm the SNS subscription email on camera. Do not skip this.

> "Until I click that link the subscription reads PendingConfirmation, and
> every alarm I just built publishes into a void. The scanner calls an
> unconfirmed alert path a HIGH, not a warning — you built the entire chain
> and it still pages nobody."

### Beat 9 — the ordering rule that bites everyone

```powershell
python attack\emit.py
```

> "I have to emit again. A metric filter only evaluates events ingested
> **after** the filter exists. Everything I emitted while blind is not counted
> retroactively. Miss this and you'll swear the alarm is broken."

Wait for the alarm period, then:

```powershell
python detect\detect.py --project hwz --region us-east-1
```

Green **WIRED**. Refresh 5110 — every card green, alarms now genuinely
PRESENT rather than merely unexamined. Then show the email in your inbox.

> "That's the whole job. It happened, and a human found out."

### Beat 10 — cost and teardown

On camera, itemised:

| Resource | Billing | Lab cost |
|---|---|---|
| GuardDuty detector | per GB analysed | pennies at lab scale |
| AWS Config recorder + 3 rules | per configuration item + per evaluation | pennies |
| Security Hub | per check per account | pennies |
| SNS topic + email | first 1,000 emails free | $0 |
| CloudWatch metric filters + alarms | first 10 alarms free | $0 |
| CloudWatch Logs ingest | per GB, we wrote kilobytes | ~$0 |
| Lambda producer | per invocation, free tier | $0 |
| Fargate producer | per second, only while running | fractions of a cent |
| EC2 producer *(off by default)* | ~$0.01/hr | $0 unless enabled |
| Foundation (VPC, S3, KMS, CloudTrail) | KMS key ~$1/mo prorated | pennies |

> "No NAT gateways anywhere in this course. That's deliberate — a NAT gateway
> is forty-five dollars a month to sit there doing nothing, and it's the
> number one way people get hurt by a lab."

```powershell
cd foundation
terraform --% destroy -var-file=hardened.tfvars
```

Verify nothing survived, on camera:

```powershell
aws guardduty list-detectors --region us-east-1
aws sns list-topics --region us-east-1 --query "Topics[?contains(TopicArn,'hwz')]"
aws logs describe-log-groups --log-group-name-prefix /hwz-lab --region us-east-1
```

> "Destroy is a claim. This is the receipt."

### Outro

> "Next chapter we put a language model behind this API, and the first thing
> we do is get it to hand over data it was never supposed to touch."

---

## Chapter 11 — LLM Security, Guardrails and WAF

**Status: complete, both labs exist.** Target 25–30 minutes.

### Pre-roll

```powershell
cd ...\module-04-llm-security
```

Second terminal for the injection lab. Browser on `http://localhost:5111`.

### Beats

1. **The claim.** *"Everything we've hardened so far assumed the attacker sends
   requests. Now the attacker sends words, and the words are the payload."*
2. **Deploy weak, then scan.**
   ```powershell
   cd foundation
   terraform --% apply -var-file=baseline.tfvars
   cd ..
   python scan\scan.py
   ```
   Note this module now genuinely composes the Chapter 8 foundation and the
   Chapter 9 API. Say so — *"forty-plus resources, and only the guardrail layer
   is weak."*
3. **Attack, CLI.** `python attack\inject.py` — the injection lands.
4. **Attack, visual.** The injection lab is the video centrepiece:
   ```powershell
   cd ..\prompt-injection-lab
   $env:PORT=5111
   python app.py
   ```
   Load the poisoned ticket, run **Vulnerable**, watch the secret light up red
   and the verdict read **BREACH**. Then flip to **Hardened**, same ticket, and
   read **BLOCKED**.
5. **The lesson between the two runs.** *"Same input. Same model. The only
   difference is a boundary between instructions and data."*
6. **Harden and prove.** `terraform apply -var-file=hardened.tfvars`, then
   `python scan\scan.py` again, then `python fix\fix.py` to show the remediation
   path.
7. **Cost and teardown.** The WAF web ACL is the only new billable line here —
   a few dollars a month, prorated to pennies for a session. Destroy, verify.

### Outro

> "The guardrail held. Next we give the model tools, and a tool is a hand
> reaching out of the sandbox."

---

## Chapter 16 — The Lab Console

**Status: exists.** Target 10–12 minutes. Shoot this third; it ties the set
together and it is the easiest episode you will make.

```powershell
cd ...\hwz-lab-console
$env:PORT=5116
python app.py
```

Walk the eight cards, flip each between weak and hardened, and land the point:

> "Every card here is a chapter you built. This isn't a dashboard I made up —
> each verdict is the same verdict the scanner in that module prints. One
> source of truth, rendered twice."

Then the port scheme on screen: `5100 + chapter`. Ch8 is 5108, Ch10 is 5110,
Ch13 is 5113, this console is 5116.

---

## Chapter 8 — Build the Cloud Foundation

**Status: CLI only — no visual lab yet.** Record the CLI now, drop the visual
segment in later, or wait. Target 30–35 minutes; this is the longest lab.

### Beats

1. **The claim.** *"Every AI breach you've read about started as a cloud
   breach. Before we secure anything with the word 'AI' in it, we build the
   ground it stands on."*
2. **Deploy weak.**
   ```powershell
   cd module-01-cloud-foundation\foundation
   terraform --% init
   terraform --% apply -var-file=baseline.tfvars
   ```
   Introduce `--%` here, once, and explain it.
3. **Scan.** `python scan\scan.py` — the findings across VPC, S3, KMS, IAM,
   CloudTrail.
4. **The Console walk.** Every finding, found by hand in the AWS Console. This
   is the chapter where students learn to navigate.
5. **Harden.** `terraform apply -var-file=hardened.tfvars`, read the diff.
6. **Rescan.** Same tool, clean.
7. **`fix/fix.py`.** Show the remediation path for an account you did not build
   with Terraform — because that is the account they will inherit at work.
8. **Cost and teardown.** KMS key is ~$1/month prorated; everything else is
   effectively free at lab scale. No NAT gateway, say it out loud. Destroy,
   then verify with `aws s3 ls` and `aws ec2 describe-vpcs`.

---

## Chapter 9 — API Security Foundations

**Status: CLI only — no visual lab yet.** Target 25 minutes.

### Beats

1. **The claim.** *"The model is not your attack surface. The API in front of
   it is."*
2. **Deploy.** `cd foundation; terraform --% apply` — composes the hardened
   foundation and adds a private Bedrock path plus a one-model role.
3. **Run the API weak.**
   ```powershell
   $env:HWZ_PROFILE="baseline"
   python -m uvicorn app.main:app --port 8000
   ```
4. **Attack.** `python attack\attack.py --url http://localhost:8000` — wrong
   audience token accepted, oversized prompt accepted, no cost cap.
5. **Harden in the app, not the cloud.** `$env:HWZ_PROFILE="hardened"`, restart,
   attack again. Every attack blocked.
   > "The weakness here was never in AWS. It was in four lines of config. That's
   > most real API breaches."
6. **Cost and teardown.** The Bedrock interface endpoint is the one hourly
   resource — roughly a cent an hour. Destroy it at the end of the session.

---

## Chapters 12 and 13 — MCP and Agentic

**Status: CLI labs exist, visual labs do not.** Both modules now genuinely
compose the layers beneath them, which changes what students see on apply — say
so on camera. Same seven beats; entry points are:

- Ch12: `python scan\scan.py`, `python attack\toolattack.py`, `guard/toolguard.py`
- Ch13: `python scan\scan.py`, `python attack\agentattack.py`, `guard/agentguard.py`

Chapter 13's headline: three proven layers underneath, one weak layer on top.

> "By the time an agent exists, three layers of control already exist beneath
> it, and I proved every one with a scan I ran myself. The agent isn't defended
> by one clever control. It's defended by everything I built before it."

---

## Chapters 14 and 15 — Vibe Coding and the Capstone

**Status: blocked. The modules do not exist yet.** The Lab Console advertises
both cards; there is no code behind either. Do not schedule these until
`module-07-vibe-coding` and `module-08-capstone` are in the repo.

When they land, Chapter 15 is your best episode: one poisoned ticket crossing
all four pillars, the naked chain completing in silence, then the same ticket
hitting four independent locks.

---

## Chapters 17–20 — the career half

Talk to camera, no lab, 12–18 minutes each. Portfolio, Communicating Risk, The
Job Search, What's Next. Record these on a day when AWS is not cooperating —
they need nothing but you.

For Chapter 17, the artifacts students already have if they followed along: the
before-and-after scanner output for every module, the BLIND-to-WIRED console
pair, and the BREACH-to-BLOCKED injection pair. That is a portfolio, and it is
better than most.

---

## What has to get built before this script is complete

1. `module-07-vibe-coding` — the Chapter 14 CI gate lab.
2. `module-08-capstone` — the composed root and the end-to-end attack.
3. Visual labs for chapters 8, 9, 12 and 13.
4. Runbooks for modules 04, 05 and 06 (10 and the rest have them).
5. The CloudWatch log-reading masterclass section in Chapter 10.
6. The cost-and-teardown closer standardised across every chapter.

---

Build it. Release it. Break it. Harden it.
