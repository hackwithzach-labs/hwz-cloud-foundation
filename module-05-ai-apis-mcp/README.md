# Module 5 — AI APIs and MCP (Pillar 2): tools, MCP, and the confused deputy

The code behind **Chapter 12**. Give a model tools through an MCP server, deploy
it with no locks, and watch it delete an account on a stranger's say-so, get
talked into fetching the cloud metadata endpoint, and answer any caller — then
lock every door.

```
scan/scan.py          hwz-scan for the tool layer: 5 gaps unlocked, PASS locked
guard/toolguard.py    tool-call guardrail (call + result), offline --selftest
attack/toolattack.py  mock-safe tool-abuse harness: 5/5 -> 0/5 guarded
fix/fix.py            hwz-harden: lock the MCP + tool layer
foundation/           Terraform: per-tool least-privilege roles + the 5 flags
  modules/tools/      scoped roles (least priv) vs one broad shared role (weak)
  baseline.tfvars     all five locks off
  hardened.tfvars     all five on
TEACH.md HARDEN.md HOMEWORK.md LESSON.md   the chapter, the control map, the work
```

## The loop

```
terraform apply -var-file=baseline.tfvars    # deploy unlocked
python3 scan/scan.py                          # 5 gaps
python3 attack/toolattack.py                  # 5/5 abuses succeed
python3 fix/fix.py                            # harden (or -var-file=hardened.tfvars)
python3 scan/scan.py                          # PASS
python3 attack/toolattack.py --guarded        # 0/5
python3 guard/toolguard.py --selftest         # 18 blocked / 20 allowed / 8 caught
```

## What gets hardened, and where

See **HARDEN.md** for the full control-by-control map. In short: authenticate the
MCP server and keep it private, give every tool its own least-privilege role,
allowlist + schema-check tool calls, lock egress to kill SSRF, keep secrets in
Secrets Manager, and extend the Chapter 11 guardrail to vet both the tool call
and its result — every block logged into the Chapter 10 SOC.

Runs offline against mock tools and a mock MCP by default — **attack only what
you own.**

© 2026 Vigilantia Technologies INC. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
