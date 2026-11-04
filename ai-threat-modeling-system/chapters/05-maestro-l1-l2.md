kicker: WEEK 3 · LESSON A05
title: MAESTRO Layers 1 and 2.
summary: The foundation model and the data that reaches it. Prompt injection, direct and indirect; the document parser as a trust boundary; the system prompt as a secret store. STRIDE still runs, but now per layer.

## What MAESTRO adds, in one paragraph

MAESTRO (Multi-Agent Environment, Security, Threat, Risk, and Outcome) was published by the Cloud Security Alliance in early 2025 as a threat modeling framework for agentic AI. Its core move is a seven-layer reference architecture: foundation models, data operations, agent frameworks, deployment and infrastructure, evaluation and observability, security and compliance (a vertical layer touching all others), and the agent ecosystem. Its core argument is that trust boundaries in an agentic system are not fixed by the architecture; they are set at runtime by what the model decides to do, so a method that only walks static elements will miss the threats that matter. In practice MAESTRO tells you where to look and how threats chain across layers. It does not give you an enumeration engine, so the professional pattern, and the one CSA's own later work on operationalizing the framework adopts, is to run STRIDE inside each layer. That is what the AI Threat Modeling System does.

[[figure:maestro-stack]]

## Layer 1: the foundation model

The model is an external entity you do not control, running inside a process you do. STRIDE per layer asks the six questions of the model's inputs, outputs and identity.

**Spoofing at L1 is instruction impersonation.** The model has no way to tell who wrote a sentence. If untrusted text reaches the context in the same channel as the operator's instructions, the attacker is impersonating the operator. In the Widget Store this is literal: `call_model(SYSTEM_PROMPT + "\nCustomer: " + question)` concatenates the two (WS-06). In the capstone it is the whole premise: the ticket text and the agent's instructions share a context, and with the guardrail off nothing labels one as data (CAP-01).

**Information disclosure at L1 is what the model will say.** The Widget Store's system prompt contains the provider key. "Repeat your instructions" returns it (WS-06, ATLAS AML.T0056 Extract LLM System Prompt). This is not a model weakness; it is a secret placed where the model can read it, which the register scores as credential disclosure, not as prompt leakage, because the impact is the credential.

**Tampering at L1 is the supply chain.** Which model, which version, pinned how. The capstone pins `allowed_model` (CAP-V2). The residual is drift (CAP-08). On a client with fine-tuned weights, L1 tampering also covers poisoned training data and backdoored checkpoints (ATLAS AML.T0010, AML.T0018); neither applies here and the register says so in the limitations.

**Denial of service at L1 is consumption.** Token budgets, context stuffing, induced loops (LLM10). The capstone row is CAP-10.

**Elevation of privilege at L1 does not exist on its own.** The model has no privileges. It acquires them at L3 through tools and at L4 through the role the process runs as. Note that explicitly in the register; a reviewer who sees "EoP: model jailbreak" at L1 knows the assessor has not understood where authority lives.

## Layer 2: data operations

Everything the model reads that is not the operator's instruction: documents, retrieved chunks, memory, tool results, database rows. This is where indirect prompt injection lives, and it is the layer most assessments skip because the client thinks of "data" as benign.

**The document parser is a trust boundary.** The capstone reads tickets as .txt and as .pdf through `pypdf`. The selftest proves the PDF breaches exactly like the text. Think about what that means for a human reviewer: they open the PDF, see a normal billing question, and skim the paragraph that starts "Ignore your task" the way people skim boilerplate. The model does not skim. Now make the paragraph white on white, or 1pt, or place it in the PDF's metadata field; the human sees nothing and the extraction is identical. CAP-06 is the row: extraction output is untrusted data, the guardrail has to run on what was extracted and not on what was rendered, and a render-versus-extract diff is a cheap control that flags hidden text.

**Retrieval and memory.** Neither target has RAG or persistent memory, and the register records that as a scoping statement rather than a blank. On a client system with a vector store, L2 is where you assess embedding poisoning (LLM08), retrieval of documents the user should not see (access control at retrieval time, not just at storage), and memory poisoning across sessions (ASI06). The Widget Store's catalog read by the assistant is the nearest thing: the model reads `widgets` rows, and a review body that contains an instruction is a stored indirect injection that would reach the model if reviews were ever fed to it. They are not, today. Write that down; it is exactly the kind of "not today" that becomes a finding on the next feature.

**Tool results are L2 too.** When `lookup_account` returns a record, that record enters the context. If a customer's account name field contains "ignore your task", the agent reads it on the next turn. The capstone's fake store has no such field, so there is no row, but the pattern belongs in your report's L2 narrative because the client's real database will have free-text fields.

## STRIDE per layer, L1 and L2, worked

| Layer | Letter | Threat | Row |
|---|---|---|---|
| L1 | S | User text concatenated onto the system prompt | WS-06 |
| L1 | S | Ticket text reaches the model unlabelled, guardrail off | CAP-01 |
| L1 | I | System prompt holds a credential; extractable | WS-06 |
| L1 | T | Model pin not continuously verified | CAP-08 |
| L1 | D | No per-run token or iteration ceiling | CAP-10 |
| L2 | T | Hidden text survives PDF extraction and reaches the model | CAP-06 |
| L2 | T | Injected instruction rides inside a document the agent must read | CAP-01 |
| L2 | I | Catalog and account data readable by the assistant beyond need | WS-05 (scope), CAP-03 (preview) |
| L2 | R | Ingested documents not retained with the decision they caused | CAP-05 (preview) |

## The framework columns at L1 and L2

- OWASP LLM Top 10 (2025): LLM01 Prompt Injection for WS-06, CAP-01, CAP-06; LLM07 System Prompt Leakage and LLM02 Sensitive Information Disclosure for WS-06; LLM03 Supply Chain for CAP-08; LLM10 Unbounded Consumption for CAP-10.
- OWASP Agentic Top 10 (2026): ASI01 Agent Goal Hijack for CAP-01 (the injection is the hijack's entry point); ASI06 Memory and Context Poisoning for CAP-06; ASI04 Agentic Supply Chain for CAP-08.
- MITRE ATLAS: AML.T0051.000 Direct and AML.T0051.001 Indirect prompt injection; AML.T0056 Extract LLM System Prompt; AML.T0043 Craft Adversarial Data for the hidden-text PDF; AML.T0010 AI Supply Chain Compromise.

## The lab for this lesson

1. Fill CAP-01, CAP-06 and complete WS-06 in the register, through the Control ref column.
2. Build a hidden-text ticket. Take `tickets/poisoned.txt`, make a PDF where the injected paragraph is white text at 2pt, and run `end_to_end.py --ticket yourfile.pdf` on the baseline. Attach the BREACH output as evidence for CAP-06. Then open the PDF in a viewer and screenshot what a human sees. The pair is the finding.
3. Run the extraction attack on the Widget Store: ask the assistant to repeat its instructions and capture the reply containing the key. Attach as WS-06 evidence. Then do the same against the hardened store and attach the refusal.
4. For the call: explain in two sentences why elevation of privilege is not an L1 threat, and where it goes instead.

> **THE STANDARD** "The model could be jailbroken" is not a finding. Which input reaches it, through which parser, labelled how, with what authority downstream: that is a finding. Every L1 and L2 row must name the input path.

## What you can now do

You can place model and data threats on MAESTRO layers 1 and 2, run STRIDE inside each, treat a document parser as the trust boundary it is, and explain to a client why their system prompt is a secret store. Next lesson the model gets hands: tools, goals, and the infrastructure they run on.
