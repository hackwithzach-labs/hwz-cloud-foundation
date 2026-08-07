# SESSION RESUME — HackWithZach Course Rebuild
### Trigger phrase: "resume from module-3"
### When the user types that, READ THIS FILE FIRST, then continue from "WHERE WE ARE RIGHT NOW".

Last updated: this file is the single source of truth for resuming the project.
Path on disk: `C:\Users\hackwithzach\Claude-Cowork\PROJECTS\rebuild\SESSION-RESUME.md`
(also committed into the repo root as `SESSION-RESUME.md`).

---

## THE PROJECT

Rebuilding Zach Marcy's flagship course **"Cloud and AI Security Engineer: From
Zero to Hired"** (brand: HackWithZach / Vigilantia Technologies INC). Three
parallel workstreams:

1. **The book (PDF)** — LIGHT ($27) and FULL ($97) editions, built by
   `light-pdf/build_pdf.py` (reportlab + cairosvg).
2. **The module code (git repo)** — the hands-on labs, one per hardening
   chapter, in GitHub `hackwithzachcs/hwz-cloud-foundation`.
3. **The live AWS "speed run"** — actually deploying each module on real AWS and
   running its weak→hardened loop, live, as Zach follows along in PowerShell.

Zach is a Cybersecurity Architect and teacher. He teaches this to students via
Instagram/YouTube/courses, so **he wants everything taught in depth so he can
teach it** (see STANDING RULES).

---

## PATHS & REPO LAYOUT (important — there is nesting)

- Everything lives under `C:\Users\hackwithzach\Claude-Cowork\PROJECTS\rebuild\`
- **Git repo root** = `rebuild\module-01-cloud-foundation\` → remote
  `github.com/hackwithzachcs/hwz-cloud-foundation`, branch `main`.
  Last pushed commit: **8b6390d** ("Add Lab Console map banners + API root landing route").
- Inside the repo root, the modules are siblings:
  - `module-01-cloud-foundation\` (NESTED — this inner folder is the Ch8
    foundation module: `foundation/`, `scan/`, `fix/`)
  - `module-02-api-security\`  (Ch9 API)
  - `module-03-observability-detection\`  (Ch10 — CURRENT)
  - `module-04-llm-security\`  (Ch11 Pillar 1 LLM)
  - `module-05-ai-apis-mcp\`  (Ch12 Pillar 2 MCP)
  - `module-06-agentic-ai\`  (Ch13 Pillar 3 Agentic)
  - `prompt-injection-lab\`  (the video-lab IPI harness)
  - `hwz-lab-console\`  (the unified GUI Lab Console, Flask, port 5000)
- **PDF build workspace** = `rebuild\light-pdf\` (SEPARATE from the git repo).
  Chapters `ch01..ch20`, `build_pdf.py`, `assets/`, and both built PDFs live here.

Module number = chapter number minus 1 from Ch8 on:
Ch8→module-01, Ch9→module-02, **Ch10→module-03**, Ch11→module-04, Ch12→module-05,
Ch13→module-06.

---

## STANDING RULES (the user set these — honor them every turn)

1. **Teach in depth, always.** For every step give: the concept, the
   architecture, what each command actually does, what to expect, and how to
   frame it for students. Not just commands.
2. **Verify in BOTH the CLI and the AWS Console (GUI)**, step by step, line by
   line. The Module-3 runbook (`module-03-DEPLOY-TEACH-VERIFY.md`) is the model
   for this — do the same for every module going forward.
3. **Console-map banners**: every module's scanner/attack prints a "LAB CONSOLE
   MAP" banner tying its CLI output to the matching Lab Console card
   (weak=red / hardened=green). Already added to all 6 scanners + module-02
   attack (committed 8b6390d).
4. **Reprovision as we go**: deploy → scan/attack weak → harden → scan/attack →
   **teardown** between every module. Never leave a stack up. Each pillar module
   composes its OWN pinned-hardened foundation. (Confirmed from the book:
   build → harden → tear down; "one apply at session start, one destroy at end.")
5. The three views tell one story: **terminal (CLI)** ⇆ **AWS Console (GUI)** ⇆
   **Lab Console card at :5000**.

---

## ENVIRONMENT GOTCHAS (these bit us — apply them proactively)

- **Terraform is a WinGet shim** (`...\WinGet\Links\terraform.exe`) and Windows
  PowerShell 5.1 mangles its flags → "Too many command line arguments." FIX:
  ALWAYS use the stop-parsing token: **`terraform --% <args>`**
  (e.g. `terraform --% apply -var-file=baseline.tfvars -auto-approve`).
- **PowerShell env vars**: use `$env:HWZ_PROFILE="baseline"` on its own line —
  NOT the bash form `HWZ_PROFILE=baseline uvicorn ...`.
- **Git stale lock**: if commits fail with `Unable to create .git/index.lock`,
  run `Remove-Item .git\index.lock` then re-add/commit/push.
- **Don't re-paste terminal scrollback** into PowerShell; a `>>` prompt means
  it's waiting for more input — press Esc/Enter to clear.
- **uvicorn** does not auto-reload on code edits; restart it (or use `--reload`).
  Port-in-use error 10048 = an old uvicorn still holds :8000; Ctrl+C it or
  `Get-NetTCPConnection -LocalPort 8000 | ... Stop-Process`.
- **detect.py / live scanners need boto3 + AWS creds** — reuse the venv at
  `module-02-api-security\.venv` (has boto3).
- Zach runs all `git push` and all live AWS `terraform` himself in PowerShell
  (his GitHub auth + his AWS SSO). I prepare files; he pushes/deploys.

---

## WHERE WE ARE RIGHT NOW  ← START HERE ON RESUME

**Live speed run progress:**
- ✅ **Module-01 (Ch8 Foundation)** — deployed hardened, validated PASS, torn
  down clean (42/39 destroyed; secret recovery_window=0 and KMS alias release
  verified).
- ✅ **Module-02 (Ch9 API)** — deployed (composed hardened foundation + Bedrock
  endpoint + API role), ran the **baseline attack** (3/4 SUCCEEDED + red
  "BREACHED" banner confirmed live), torn down. Added an API **root landing
  route** (`GET /` shows profile + the 4 control states; `/docs` is Swagger).
  NOTE: the **hardened** attack half (all BLOCKED / green banner) was skipped —
  it's local/free and can be run anytime for the green screenshot.
- ⏳ **Module-03 (Ch10 Observability & Detection) — CURRENT. At Phase 1 (deploy
  BLIND), NOT yet run.** The full runbook was delivered:
  `module-03-DEPLOY-TEACH-VERIFY.md` (deploy + teach + verify in CLI AND Console,
  line by line). Next action = have Zach run Phase 1:
  ```powershell
  cd C:\Users\hackwithzach\Claude-Cowork\PROJECTS\rebuild\module-01-cloud-foundation\module-03-observability-detection\foundation
  terraform --% init
  terraform --% apply -var-file=baseline.tfvars -auto-approve
  ```
  Then Phase 2 = `python detect\detect.py` (red BLIND banner) + walk the 8 AWS
  Console screens confirming each detection link is ABSENT. Then Phase 3 harden
  (`-var-file=hardened.tfvars -var alert_email=...`), Phase 4 verify WIRED
  (green), Phase 5 teardown.

**Module-03 detail (from detect.py):** 8 checks —
metric filters `unauthorized-access` (401/403) & `cost-cap-breach` (429);
alarms on them; EventBridge rules `cloudtrail-tamper`, `sg-open-to-world`,
`root-account-use`; SNS alert path (confirmed subscription); GuardDuty; Config;
Security Hub; CloudTrail→S3 for Athena. Toggle: `baseline.tfvars`
(detections_enabled=false, BLIND) vs `hardened.tfvars` (true, WIRED). Hardened
may need `-var alert_email=YOU@EXAMPLE.COM` for the SNS subscription.

---

## DELIVERABLES ALREADY PRODUCED THIS SESSION

- **PDFs** (in `light-pdf\`, delivered): LIGHT **138pp** / FULL **150pp**. New
  since baseline: About Zach page (headshot `assets/zach.jpg`), edition-aware
  lab-map TOC (LIGHT frames labs as a Full-edition teaser w/ upgrade CTA),
  **Ch16 "The Lab Console"** (walkthrough w/ 8 weak-vs-hardened screenshots),
  four **career chapters 17–20** (Portfolio, Communicating Risk, Job Search,
  What's Next), and a **GO DEEPER / FIND ME** back-matter page. build_pdf.py now
  embeds PNGs (not just SVG); career-chapter cross-refs fixed for the renumber.
- **Lab Console** (`hwz-lab-console/app.py`) — Flask, 8 module cards, WEAK/HARDENED
  toggle, live counts from module-05/06 scanners. In repo, pushed.
- **Module-03 runbook** `module-03-DEPLOY-TEACH-VERIFY.md` (delivered).

---

## PENDING / BACKLOG

1. Finish **Module-03** live run (Phase 1→5, CLI+Console, taught in depth).
2. Then **Module-04 (Ch11 LLM/injection)**, **Module-05 (Ch12 MCP)**,
   **Module-06 (Ch13 Agentic)** — same deploy→teach→verify(CLI+GUI)→teardown loop.
   Build a DEPLOY-TEACH-VERIFY runbook for each, like module-03's.
3. Optional: **wire the commented-out foundation composition** in module-04/05/06
   so they build hardened-on-hardened live like 02/03 (currently their
   `module "foundation"` / `api` / `mcp` blocks are commented out; only their own
   layer deploys). This diverges from the book's "runs against mocks" cost notes —
   confirm with Zach before doing it.
4. Optional: module-02 **hardened attack** (local, green banner screenshot).
5. Optional: three missing capstone figures `fig-13-1`, `fig-14-1`, `fig-15-1`
   (currently placeholder refs in the FULL PDF).

---

## SIDE FACTS (asked about this session)

- Kit (ConvertKit): the cohort access email **"You are in the Full cohort. Here
  is your access."** is processed by the Kit **email sequence "Upgrade delivery
  (cohort access)"** (`app.kit.com/sequences/2847188`), a 0-day 1-email sequence
  set to send **Immediately** on Full upgrade; 13 subscribers, ~77% open. Its
  Discord/"meetings" link and PDF link are **per-subscriber merge fields**
  `{{ subscriber.discord_invite }}` and `{{ subscriber.download_url }}` — the
  actual call schedule/calendar invite lives inside Discord, not in the email.

---

## RESUME CHECKLIST (do this when "resume from module-3" is typed)

1. Read this file top to bottom.
2. Confirm repo/branch state on device (`git log --oneline -1` should show
   8b6390d or later; `git status` clean).
3. Re-open the AWS Console (region us-east-1) and the Lab Console (:5000) tabs.
4. Resume at **Module-03 Phase 1** above, teaching in depth, verifying CLI+GUI.
