# HackWithZach — Lab Console

The unified visual lab for **Cloud and AI Security Engineer: From Zero to Hired**.

Every hands-on chapter ships a CLI lab you deploy from Git (`scan` / `attack` /
`fix`, each with an offline `--selftest`). This console is where each chapter
**bundles** that lab into one branded browser dashboard: pick a module, flip it
between **WEAK** (red) and **HARDENED** (green), and watch the same attack
succeed on the naked build and die on the hardened one — the same story the
scanners and attack harnesses print, made visual for the walkthrough.

It is the GUI companion to the indirect-prompt-injection video lab, extended to
cover all four pillars and all eight hands-on chapters.

## Run it

```bash
pip install -r requirements.txt
python app.py
# open http://localhost:5116
```

## Live counts

Drop this folder at the **root of the monorepo** (as a sibling of the
`module-01-cloud-foundation/` … `module-06-agentic-ai/` directories) and the
console imports the real scanners at boot and recomputes the finding counts
**live** — the modules it can reach get a green **LIVE** badge and a `live: N`
annotation on their verdict. Run it standalone (anywhere else) and it shows the
same verified results the module `--selftest`s produce. Either way the numbers
are the truth.

## What each card shows

| Ch | Pillar | Module (CLI lab, from Git) |
|----|--------|-----------------------------|
| 8  | Cloud | Cloud Foundation — `hwz-scan` the account |
| 9  | Cloud | API Security — weak vs hardened profile |
| 10 | Cloud | Observability & Detection — blind vs wired SOC |
| 11 | Pillar 1 · LLM | Prompt Injection — the video lab |
| 12 | Pillar 2 · AI APIs & MCP | MCP Tool Abuse — 5 abuses |
| 13 | Pillar 3 · Agentic | Agent Loop — 5 abuses |
| 14 | Pillar 4 · Vibe Coding | AI-Generated Code Gate |
| 15 | Capstone | End-to-End — one attack, every layer |

## Routes

- `GET /` — the dashboard.
- `GET /api/run/<key>/<posture>` — JSON for one module/posture
  (`posture` is `weak` or `hardened`); the same payload the cards render.

---

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are
trademarks of Vigilantia Technologies INC. Education and defense only — attack
only what you own.
