# SecureAI Support Console, GUI Quickstart

The live, on-screen version of the lab. A black/red/white support desk you run
locally in the browser: pick a ticket, choose the Vulnerable or Hardened build,
send it, and watch the leak or the block happen in real time. This is the app to
film the walk-through on.

## Run it (Windows PowerShell)

From inside the `prompt-injection-lab` folder:

```powershell
pip install flask

# In a SECOND terminal, start your local model:
ollama serve
ollama pull llama3.1      # a tool-capable model (only needed once)

# Back in the first terminal:
python app.py
```

Then open http://localhost:5000 in your browser.

macOS / Linux is the same, minus the PowerShell quirks.

## The 20-second walk-through (what you do on camera)

1. Model dropdown: leave it on **Ollama (local, real model)**.
2. Build toggle: **Vulnerable**. Click **Poisoned ticket**, then **Send to agent**.
   You get a red **BREACH** banner, the leaked key lit up in red, and a security
   log that says *No detections. The attack was invisible.*
3. Flip the toggle to **Hardened**. Click **Send to agent** again, same ticket.
   Red turns to green: **BLOCKED**, the tool returned Jordan's record (not the
   admin's), and three detection events appear in the security log.

That flip, red to green on the exact same attack, is the whole video in one screen.

## Model dropdown

- **Ollama (local, real model)** — a genuine model getting fooled, on your own
  box. No key, no cloud, no cost. This is the credible take.
- **Simulation (safe take)** — deterministic, guaranteed-clean. Your safety net
  for re-takes, and identical on screen. No Ollama needed.

## If a real model resists the attack

Real models vary. If Ollama does not leak on the first try, either strengthen the
injected line in the ticket box (attackers tune payloads too, and saying so on
camera is honest), or switch a heavier local model:

```powershell
$env:HWZ_OLLAMA_MODEL = "qwen2.5"
python app.py
```

## Notes

- The terminal CLI lab (`agent_vulnerable.py`, `agent_hardened.py`) still works
  exactly as before, for the code-on-screen shots. The GUI and the CLI run the
  identical logic, so they tell the same story.
- Nothing here is real: the account store is fake and the "secret" is a made-up
  string. Attack only what you own.

© 2026 Vigilantia Technologies INC. HackWithZach.
