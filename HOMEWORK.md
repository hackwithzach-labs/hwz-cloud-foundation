# Week 1 Homework: The Cloud Foundation

Cohort co-build. This is the model: I rebuild the course one module at a time from the cloud up, you run it that week as homework, we meet, and once it works clean for you I record it and we move to the next module. Your job this week is to be the first person to run the new foundation end to end and tell me where it fights you.

Before you start: use an ISOLATED SANDBOX AWS account. Not production, not your employer's account. Nothing here runs an instance or a NAT gateway, so cost is close to zero, but destroy it when you finish anyway.

## 1. Build it

```bash
cd foundation
terraform init
terraform apply -var-file=baseline.tfvars
```

Report back the one thing that matters most: did it apply clean on the first try, with no missing variables, no missing outputs, no undefined resources? That is the bar the old chapter failed. If anything screams at you, copy the exact error and send it. That is a bug in my code, not a gap in your knowledge, and I want it.

## 2. Break it

The baseline is wide open on purpose. Walk it and find every hole. For each one, write a single sentence: what does this let an attacker do?

Prompts to guide you, one per layer:

- The endpoint security group. Who can reach it, and why is that bad?
- The S3 data bucket. Three separate problems. Name them.
- The workload IAM role. What is the worst single action it is allowed to take?
- The KMS key policy. Who can use the key?
- CloudTrail. It is running. Why is a running trail not the same as useful evidence? Name at least two reasons.

You should end up with roughly ten findings. Bring that list to the call.

## 3. Harden it

Read `HARDEN.md` first, then:

```bash
terraform plan -var-file=hardened.tfvars
```

Do not apply yet. Read the plan. For every changed line, match it to a finding from step 2. If there is a change you cannot explain, mark it and bring it. Then apply:

```bash
terraform apply -var-file=hardened.tfvars
```

Re-walk the stack. Confirm each hole from step 2 is closed.

## 4. Tear it down

```bash
terraform destroy -var-file=hardened.tfvars
```

Confirm it destroys clean. If anything is left behind in the console, tell me, because a teardown that leaves resources is its own bug.

## What to send me before the call

1. Did baseline apply clean, yes or no. If no, the exact error.
2. Your findings list from step 2.
3. Any hardened-plan line you could not map to a finding.
4. The single biggest thing that was unclear. Not to be nice, to make the recording better for the next person.

This is the part I need your help with most. You are in it, so you can see the gaps I cannot. Same deal as before, this is on the house.

---

Build it. Release it. Break it. Harden it.

© 2026 Vigilantia Technologies INC. All rights reserved. "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
