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

## Why the command line and code, not the console

You could build all of this by clicking through the AWS console. You are not going to, and understanding why is itself a senior skill. Every resource in this program is declared as code, in this repository, and deployed from the command line. The console is where you look, not where you build.

Here is what infrastructure as code gives you that clicking never will.

It is reproducible. The same code produces the same environment every time, on any machine, for any person. A console build is a sequence of clicks nobody wrote down, and two people get two different results neither can prove.

It is version controlled. The infrastructure lives in git, so every change is a diff with an author, a date, and a reason, and you can roll back. The console keeps no history of who changed what or why.

It can be reviewed before it is real. Code goes through a pull request so a second person catches the mistake before it reaches AWS. A console change is live the instant you click it.

It has no drift. Manual tweaks pull an environment away from any documented state, and nobody remembers them. With code, the code is the truth and drift is detectable: `terraform plan` shows what changed by hand. It is the same reason the scanner in this program works. You can scan code and state. You cannot scan someone's memory of what they clicked.

It tears down clean. One command removes everything. Clicking to delete always misses something, an orphaned interface, a security group, a log group, that keeps costing money and stays as attack surface.

And it is the source of your security. Encryption, network rules, and permissions are written, reviewed, and scanned. Secrets never get typed into a console field.

The concrete errors this avoids are the ones that cause real incidents: the wrong region selected, a single missed checkbox like Block Public Access that makes a bucket public, a typo in a CIDR that opens a network path, settings that drift between environments, steps done in the wrong order or forgotten, a change made once and never repeatable. Every one is a click-ops failure, and every one is designed out when the environment is declared once in reviewed code and applied the same way every time.

The honest nuance: the console is fine for reading. Investigating an incident, watching a metric, confirming a scanner finding. Use it to look. Never use it to build. Building is always code, in the repository, from the command line.

## Why it is modular

The foundation is not one giant template that every pillar inherits whole. If it were, Pillar 1 would drag in a CloudTrail bucket it never uses and Pillar 3 would duplicate a VPC that already exi