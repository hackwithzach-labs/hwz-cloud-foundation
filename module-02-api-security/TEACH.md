# Module 2: API Security

Cloud and AI Security Engineer: From Zero to Hired

Build it. Release it. Break it. Harden it.

---

## Start with the end in mind

The model does not talk to the world directly. Something sits in front of it: an API. That API is where identity is checked, where input is bounded, where cost is capped, and where the record of what happened gets written. Get the API layer wrong and it does not matter how good your guardrails are, because the attacker never reaches them. They abuse the door.

This module builds that door, twice. First the way a rushed team releases it, wide open, and you attack it and watch every attack land. Then the way it should be, and you run the same attacks and watch them all fail. The difference between the two is four controls, and by the end of this module you can name each one, attack the absence of it, and prove the presence of it.

Here is the whole picture. The module-1 foundation you already built and proved is underneath, deployed hardened. On top of it sits one new thing, the inference API, and the API is the only part that starts weak.

```
        THE API (this module, weak -> hardened)
   +-------------------------------------------------+
   |  POST /v1/complete                              |
   |   1. audience-bound token verification          |
   |   2. JSON Schema on the body                    |
   |   3. per-token rate AND cost cap                |
   |   4. structured audit logging                   |
   +-------------------------------------------------+
                        |
             runs on / talks through
                        v
        THE FOUNDATION (module 1, PINNED HARDENED)
   VPC private subnets · KMS · IAM · Secrets · CloudTrail · CloudWatch
```

Read that top to bottom. The API is not floating. It assumes a least-privilege role from the foundation, it reads its credential from the foundation's Secrets Manager, and in the real deployment it reaches the model through a Bedrock endpoint sitting in the foundation's private subnets. You do not rebuild any of that. You compose it, pinned hardened, because you proved it in Chapter 8.

## Build it before you break it

Do not start with the weak app or the hardened app. Start with `app/minimal.py`, the irreducible inference API: about twenty lines, a prompt in and a completion out, no security at all. Run it (`uvicorn app.minimal:app --port 8000`) and send it a request, and watch a completion come back. Then read those twenty lines as the eight hops a request travels, and notice that four hops, who is calling, is the input sane, has this caller had enough, and did we record it, ask no question at all. Those four open hops are the four controls below. You are not bolting new stages onto the pipeline; you are guarding hops you have already watched a request pass through. That is why this module builds the API before it secures it: you cannot defend a pipeline you have never seen a request travel.

## The four controls, and the four attacks

Every control exists to stop one specific attack, and the attack script runs all four so you see the pairing with your own eyes.

Control 1, audience-bound token verification. A token is not a passport that works everywhere. It is minted for one audience, one service, and this API must reject a token minted for anything else. The weak version accepts any signed token, so a token your app handed to a different microservice is enough to call the model. The attack mints a token for `some-other-service` and walks right in. This is the broken-authorization slice of LLM06 Excessive Agency.

Control 2, JSON Schema on the body. The model costs money per token and misbehaves on malformed input. The API must bound what it accepts: the prompt is a string within a length, `max_tokens` is an integer within a ceiling. The weak version accepts anything, so a fifty-thousand-character prompt or a `max_tokens` of a million sails through. That is LLM05, improper handling of input, and it is also the on-ramp to the next attack.

Control 3, per-token rate and cost cap. This is the one that shows up on the bill. Without a cap, one caller can loop the endpoint and run your spend to the moon, the documented forty-thousand-dollar-overnight class, LLM10 Unbounded Consumption. The hardened version tracks requests and estimated spend per token and refuses once either ceiling is hit. The attack floods a single token and watches the first few succeed and the rest get refused with a 429.

Control 4, structured audit logging. When something goes wrong you get one question first: what happened, and who did it. The weak version prints an unparseable human string with no token id, no cost, no outcome, which is the same as printing nothing. The hardened version writes one structured JSON line per request, the record an investigator can actually query and the exact input the SIEM in Module 3 consumes. The attack sends a single request and you go looking for it in the log; finding it, structured, means the control works.

## Weak by policy, not broken by omission

Same rule as the foundation. The weak API is not missing an endpoint or throwing errors. It runs, it serves every request, it returns completions. It is just wide open, and every hole is one flag in `app/config.py` set to `False`. You flip the profile from `baseline` to `hardened` and the same code, same endpoint, closes every hole. The weakness is a value, not a missing resource, which is what makes it safe to teach and honest to run.

## Why the loop runs locally first

The app fronts a mock model call, so the entire build, attack, harden, attack loop runs on your laptop at zero cost and zero AWS. That is deliberate. You learn the four controls and the four attacks with nothing at stake, then the Terraform root makes it real: the foundation hardened, a Bedrock endpoint in the private subnets, a least-privilege role that may invoke exactly one model and read exactly one secret. Swap the mock call for a real Bedrock invocation and not one of the four controls changes. That is the point of a clean API layer: the controls do not care which model sits behind them.

## Cost safety, and why this module is built this way

This module teaches you to attack a missing cost cap. That is dangerous to teach carelessly, because the whole point of Control 3 is that the weak build has no ceiling on calls or tokens, and the attack floods it. If that flood ever hit a real paid model, it would be a real bill, the exact LLM10 harm you are studying. So the module is built to make that impossible by construction, and you should understand the design because it is the professional pattern you will reuse on the job.

The attack runs against a mock. `mock_model_complete` in `app/main.py` returns a fake completion at zero cost, and the flooding attack is demonstrated there. You see it succeed, you learn why the missing cap is dangerous, and nothing charges you.

Every build carries an always-on breaker. `app/config.py` defines `ABS_MAX_MODEL_CALLS_PER_PROCESS` and `ABS_MAX_TOKENS_PER_CALL`, and `safety_breaker()` in `app/main.py` enforces them before every model call, in every profile. This is NOT Control 3, the teaching cap that baseline turns off. This breaker can never be turned off. Its job is not to teach; its job is to keep a mistake to pennies if you ever wire a real model in the weak state.

We never trust cloud billing to stop a runaway. AWS Budgets alert, they do not hard-stop. That is the real lesson hiding in the safety design: the protection lives in your code, on by default, not in a billing alarm you hope fires in time. When you do the optional real-Bedrock step, it runs hardened only, pinned to the cheapest model with a tiny token ceiling, and you never point the flood at it.

## Do it now

Open `RUNBOOK.md` and run the loop. Start with `python3 attack/attack.py --selftest` to prove the attack logic with no server at all, then stand up the weak API, attack it, read the logs, harden it, attack it again, read the logs again. `HARDEN.md` walks the four controls one at a time. `HOMEWORK.md` is the week's assignment.

Keep five artifacts, same as Module 1: the weak attack output, your weak-state log note, the hardened attack output, your hardened-state log note, and the one structured audit line that proves control 4. Those go in your portfolio.

---

By Zach Marcy. Cybersecurity Architect and Mentor. 20+ years in IT, 6 in cybersecurity. I design and secure cloud environments that deploy and secure APIs and AI.

Cybersecurity Education That Gets You Hired, Promoted and Paid.

© 2026 Vigilantia Technologies INC. All rights reserved. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
