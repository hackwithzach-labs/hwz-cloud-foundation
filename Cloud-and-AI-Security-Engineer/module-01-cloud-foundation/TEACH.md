# Module 1: The Cloud Foundation

Cloud and AI Security Engineer: From Zero to Hired

Build it. Release it. Break it. Harden it.

---

## Start with the end in mind

Before you write a line of Terraform, look at what you are building and why. Most cloud courses hand you resources one at a time and never show you the board. You end up with a working VPC and no idea what it is for. This module fixes that first, then builds.

Here is the whole picture. Everything in this course, all four AI pillars, runs on top of one small, shared cloud foundation:

```
                        THE FOUNDATION (this module)
   +-------------------------------------------------------------+
   |  VPC  (public + PRIVATE subnets, routing, endpoint SG)      |
   |  KMS  (one shared customer-managed key)                     |
   |  IAM  (a workload role your apps assume)                    |
   |  S3   (a data bucket)                                       |
   |  Secrets Manager (app credentials, no rotation Lambda)      |
   |  CloudTrail (account trail + its own log bucket)            |
   |  CloudWatch (log groups + the flow-logs role)              |
   +-------------------------------------------------------------+
        ^            ^              ^                ^
        |            |              |                |
   Pillar 1     Pillar 2       Pillar 3         Pillar 4
   LLM Sec      AI APIs/MCP    Agentic AI       Vibe Coding
   (guardrails) (Bedrock in    (agents with     (AI-written
                 a private      tools + memory)   code you scan)
                 subnet)
```

Read that top to bottom. The foundation is the ground. Each pillar is a building you put on that ground. Pillar 2 does not invent its own network. It reads the private subnets and the endpoint security group this module already created, and drops a Bedrock endpoint into them. Pillar 3 does not invent its own key. It encrypts agent memory with the KMS key this module already created. That is what people mean when they say a security architect thinks in systems, not tickets. You are about to build the system.

## Who this module assumes you are

You know what a VPC, an IAM role, and an S3 bucket are. You have clicked around a cloud console. You can read a block of Terraform without panic. If that is not you yet, that is fine, the free 4 Pillars PDF and the Python for Security course are your on-ramp, and you should run those first. This course starts one rung up, because teaching cloud engineering from absolute zero and cloud security and AI security in one program is three courses wearing a trenchcoat. We assume the floor so we can get to the part that gets you hired.

## The method, applied to infrastructure

The brand loop is four steps. Here is how each step maps onto this module, so the loop is concrete and not a slogan.

Build it. You stand up the foundation with Terraform, one modular codebase, seven modules, applied with a single command. It deploys clean on the first try. That last part matters more than it sounds, and we will come back to it.

Release it. You apply the weak baseline. This is the version a rushed contractor or a first-week engineer would leave behind. It works. It serves traffic. It also has a hole in every layer. That is not an accident, it is the starting state on purpose.

Break it. You go find every hole. Scan it, or walk the console, and name each weakness: the open endpoint, the unencrypted bucket, the trail that records nothing useful, the role that can delete your evidence. You attack your own build. Not because you are a pen tester, but because you cannot harden what you have not seen fail.

Harden it. You flip the flags, run the plan, read the diff, and apply. Same code, every weakness closed. Then you re-scan and watch the findings drop to zero. `HARDEN.md` walks all five control areas one at a time.

Then you tear it down, because a lab you leave running is a bill and a liability.

## Weak by policy, not broken by omission

This is the most important idea in the module, and it is the thing the old version of this course got wrong.

There are two ways a cloud stack can be insecure. It can be weak by policy, where every resource exists and works, but the settings are loose. No encryption, an open security group, a role with too much power. That is a teachable state. You can deploy it, look at it, and fix it.

Or it can be broken by omission, where the code references a security group that has no VPC to live in, a bucket policy with the wrong ARN, an output that was never declared, a rotation Lambda that does not exist. That is not insecure, it is non-functional. It does not teach security, it teaches frustration, and it ends with a learner staring at a wall of red Terraform errors before they have learned anything.

The old cloud chapter was broken by omission. It was reverse-engineered from a working system down into stripped-back pieces, and the pieces no longer fit. This foundation is weak by policy. Every module is complete. Every variable is declared. Every output exists. The CloudTrail bucket policy is correct and the trail waits for it with a `depends_on`. The Bedrock-ready private subnets are there from the first apply. It runs clean, and it is wide open, and those two facts are both true at once. Hold onto that distinction, because it is the difference between a lab that builds confidence and a lab that destroys it.

## Why it is modular

The foundation is not one giant template that every pillar inherits whole. If it were, Pillar 1 would drag in a CloudTrail bucket it never uses and Pillar 3 would duplicate a VPC that already exists, and you would end up with sprawl, redundant resources, and tangled dependencies. That is the trap of a single golden template.

Instead the foundation is seven independent modules with clean inputs and outputs. Each pillar ships its own root configuration that calls only the modules it needs and reads the outputs it cares about. Pillar 2 pulls the VPC and the KMS key. Pillar 4 might pull only S3 and the log group. Same foundation, composed differently per pillar. That is horizontal, five small stacks that share a base, not one vertical monolith. It is how real teams keep a cloud estate sane, and it is why the network, the key, and the logging you build once here will carry you through all four pillars without a rebuild.

## The module map

| Module | Why it exists | Which pillar leans on it hardest |
|---|---|---|
| `vpc` | Somewhere private for models and agents to run | Pillar 2 (Bedrock endpoint in the private subnets) |
| `kms` | One key to encrypt data, secrets, memory, and logs | All four |
| `iam` | An identity your apps assume, scoped or not | All four |
| `s3` | Where data, artifacts, and logs land | Pillars 1, 2, 4 |
| `secrets` | Credentials out of code and into a vault | Pillars 2, 3 |
| `cloudtrail` | The record of what happened, tamper-evident | All four, and every incident you will ever work |
| `observability` | The log groups your apps and network write to | All four |

Open the `foundation/` folder, read `README.md`, and you will see these seven modules and the single root that wires them together in `main.tf`. Read `main.tf` first. It is the picture at the top of this page, written as code.

## Do this now

1. Read `foundation/README.md`.
2. Read `foundation/main.tf`. Match each `module` block to the diagram above.
3. Run the weak stack. Confirm it applies clean.
4. Break it. Find every hole and write down what each one lets an attacker do.
5. Read `HARDEN.md`, flip to `hardened.tfvars`, read the plan, apply, and confirm the holes are closed.
6. Tear it down.

Your homework for the week is in `HOMEWORK.md`. Bring your questions and your plan output to the call.

---

By Zach Marcy. Cybersecurity Architect and Mentor. 20+ years in IT, 6 in cybersecurity. I design and secure cloud environments that deploy and secure APIs and AI.

Cybersecurity Education That Gets You Hired, Promoted and Paid.

© 2026 Vigilantia Technologies INC. All rights reserved. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
