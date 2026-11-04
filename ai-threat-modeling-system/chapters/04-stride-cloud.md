kicker: WEEK 2 · LESSON A04
title: STRIDE on the Cloud and API Tier.
summary: The capstone inherits a hardened foundation and a private model path. Assessing a hardened tier is a different skill from assessing a weak one, and it is the skill that separates an architect from a scanner.

## Assessing what is supposed to be fine

The Widget Store was easy in one respect: everything was broken, so every STRIDE letter had something under it. The capstone's cloud tier is the opposite. `main.tf` pins all twelve foundation flags to true with a comment saying no weak option exists. The API module takes the private subnets and the endpoint security group from the foundation and pins the model id. If you read the comments and move on, you have done what a junior does. If you verify every pinned control with the repo's own scanner and record the verification in the register, you have done what a client pays for.

The register has a row kind for this: **Verified control**. It carries the same columns as a finding, with status Verified and no score. It matters for three reasons. The client sees what they are getting right, which makes the findings easier to accept. The auditor sees that the assessment covered the whole system and did not just report the broken parts. And you have a baseline for the retest: if a verified control regresses when the fixes land, the retest catches it.

## The cloud foundation, letter by letter

Run STRIDE against the foundation exactly as against the storefront. The difference is that most answers are "controlled by X, verified by Y". Fill the Verified column with the command.

| Letter | Threat considered | Control in main.tf | Verified by |
|---|---|---|---|
| S | Role assumed through a loose trust policy (T1078.004) | iam_scope_workload, scoped trust policies | module-01 scan PASS in the green wall |
| S | Credentials from the metadata service (T1552.005) | IMDSv2 required, least-privilege workload role | module-01 scan |
| T | Bucket policy or log rewritten (T1565) | kms_strict_key_policy, iam_deny_destructive | module-01 scan; CloudTrail PutBucketPolicy would alarm |
| R | Activity without a trail; logs without validation | cloudtrail_multi_region, log_file_validation, data_events, use_kms | module-01 scan; module-03 detect fixtures |
| I | Public or unencrypted bucket (T1530) | s3_block_public_access, default_encryption, enforce_tls | module-01 scan |
| D | Resource deletion, log stop (T1562, T1485) | iam_deny_destructive | module-01 scan; the explicit deny is the control |
| E | Over-permissioned role, privilege escalation (T1098) | iam_scope_workload, scoped trust | module-01 scan |

Every row resolves to CAP-V1. One verified-control row, with the table above as its evidence. That is the correct shape: the foundation is one asset with one posture, and the scanner proves the posture in one run.

## The API tier

| Letter | Threat considered | Control | Verified by |
|---|---|---|---|
| S | Model called from outside the VPC with stolen credentials | VPC endpoint, endpoint security group, scoped API role | module-02 selftest; the attack harness weak-versus-hardened |
| T | A different model substituted (T0010 supply chain) | allowed_model pinned in the IAM condition | CAP-V2 verified; residual CAP-08 |
| R | Model calls with no record | CloudTrail InvokeModel data events | module-03 detect |
| I | Secret for the provider exposed | secret_arn from Secrets Manager, not in code | module-02 selftest |
| D | Unbounded invocations (LLM10) | Per-tool cost caps exist in Chapter 12; not in baseline posture | CAP-10 finding |
| E | API role used for more than invoke | Scoped role | module-02 selftest |

This produces CAP-V2 and two findings that a comment-reader would miss. CAP-08: the model pin is correct today, but nothing checks it stays correct across later applies, and the audit path does not record model version. CAP-10: the course ships cost caps per tool in Chapter 12 and an always-on spend breaker for the account, but the baseline posture of the agent has no per-run iteration or token ceiling, so a looping ticket spends until the account breaker trips. The breaker protects the bill, not the run.

## Residual risk is a finding

The habit this lesson teaches is to ask, of every verified control, "and what is left?" The answer is residual risk, and residual risk goes in the register as a Low or Medium row with the verified control as its context. A client who only sees Critical and High rows learns nothing about the margin they are running on. A client who sees CAP-V1 followed by CAP-09 ("declared posture can drift from deployed posture; nothing watches the file") understands exactly how strong their strongest control is.

CAP-09 is worth dwelling on because the capstone README states it as a feature: if you edit the tfvars and forget to apply, the attack reports the old posture, which is correct. It is correct. It is also a gap: nothing alerts when intent and deployment disagree. Correct behaviour and a missing control can be the same sentence, and an assessor's job is to say both.

## What STRIDE cannot see here

STRIDE on the cloud tier will tell you about roles, buckets, trails and endpoints. It will not tell you what happens when the model is told to change its goal, because the model is an external entity to STRIDE and "external entities are mainly S and R" stops being enough when the external entity is making decisions inside your process. That is the gap MAESTRO exists for, and it is why the next two lessons move the method from elements to layers.

Before you move, note the hand-off explicitly in the register: every capstone element whose threats depend on model behaviour (planner, tools, guardrail, approver) gets a STRIDE pass that says "see MAESTRO L1 to L7". The reviewer should see that you knew where STRIDE stopped.

## The lab for this lesson

1. Run the green wall and attach it as evidence `CAP-green-wall.txt`. Then run `python3 scan/scan.py --posture foundation/posture.json` against a baseline apply if you have a sandbox account standing, or `--selftest` if you do not, and attach the output.
2. Fill CAP-V1 and CAP-V2 as Verified control rows. In the Evidence column, cite the scanner run, not the comment in main.tf. If you cannot verify a control, do not mark it verified; mark it Unverified and list it in section 4 (Limitations) of the report.
3. Fill CAP-08, CAP-09 and CAP-10 as findings. These are the residual-risk rows. Columns 1 through 8, Control and Control ref. No scores.
4. For the call: name one control in the foundation that you verified and one you would want a second method of verification for before putting your name on it. Say what the second method would be.

> **THE STANDARD** Verified means you ran it. "The Terraform says true" is a claim the client already made. Your job is to be the person who checked.

## What you can now do

You can assess a hardened tier without either rubber-stamping it or inventing problems, record verified controls as first-class register rows, and surface residual risk as findings in their own right. You know where STRIDE stops on an AI system. Next lesson you pick up MAESTRO at that exact point.
