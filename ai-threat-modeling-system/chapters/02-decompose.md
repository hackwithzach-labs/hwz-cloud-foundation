kicker: WEEK 1 · LESSON A02
title: Decompose the System.
summary: Data flow diagrams, the asset register, trust boundaries, and the MAESTRO layer map for both targets. Nothing gets threat modeled until it is drawn.

## Why decomposition comes first

Every weak threat model shares one failure: the assessor started listing threats before they knew what the system was. The list ends up reflecting what the assessor happened to know rather than what the system actually does, and the gaps are invisible because there is no structure to show them. Decomposition is the structure. You draw the system as elements and the flows between them, you mark where trust changes, you list what is worth protecting, and only then do you walk each element asking what could go wrong. STRIDE is a checklist you run against a drawing. Without the drawing there is nothing to run it against.

The deliverables of this lesson, for each system, are a level 1 data flow diagram, an asset register, a trust boundary list, and for the AI components a MAESTRO layer map. They go in section 5 of the report (Architecture and trust boundaries) and the Assets sheet of the workbook.

## Data flow diagram elements

Four element types, the same four STRIDE was designed around:

- **External entity.** Something outside your control that sends or receives data: a customer, a browser, an attacker, a provider API, an external email domain.
- **Process.** Code that transforms data: a route handler, the model call, the agent planner, a tool.
- **Data store.** Where data rests: a database table, a file, the session, the model's context window.
- **Data flow.** An arrow. Every arrow is a place where data changes hands, and every arrow that crosses a trust boundary is a place to look hard.

Level 0 is one process with its external entities. Level 1 breaks the process into the components that matter. You need level 1 for both systems; level 2 for the assistant and the agent loop, because that is where the AI-specific threats live.

## System 1: Widget Store, level 1

[[figure:ws-dfd]]

The elements, with the file reference a reviewer will want:

| Element | Type | Where | Notes |
|---|---|---|---|
| Customer browser | External | n/a | Also the attacker's browser; there is no distinction the app can make |
| Storefront | Process | weak/app.py | login, catalog, cart, checkout, review, orders, export, admin, ask in ONE process |
| Assistant | Process | call_model(), ask() | Stub model; reply parsed for DISCOUNT: |
| Shell | Process | run_shell() | subprocess with shell=True |
| store.db | Data store | weak/store.db | users (plaintext password), widgets (price), orders, reviews |
| CARTS | Data store | module dict | Keyed by user id from the query string |
| Page template | Process | PAGE, page() | Renders key into script; `|safe` on body |
| Provider API | External | (stub) | Would receive LLM_API_KEY if real |

The flows that cross a boundary are the ones to number. In the weak store there are five:

1. Browser to storefront: every request, with identity and role in the query string.
2. Storefront to store.db: queries built by string formatting.
3. Customer text to assistant: concatenated onto the system prompt.
4. Assistant reply to store.db: the DISCOUNT: write path.
5. Request value to shell: the export route.

The hardened store adds two boundaries the weak one does not have: storefront to admin service (separate process, port 5202), and WAF to every view (before_request). Draw both diagrams. The difference between them is the remediation story and it belongs in the report as a before-and-after figure.

## System 2: Agentic support agent, level 1

[[figure:cap-dfd]]

| Element | Type | Where | Notes |
|---|---|---|---|
| Customer (or attacker) | External | tickets/*.txt, *.pdf | No account required to file a ticket |
| Ingest and parse | Process | end_to_end.py load_ticket(), pypdf | Extracted text, not rendered view, reaches the model |
| Guardrail (gate 1) | Process | guardrail_enabled | Screens extracted text for injection; OFF in baseline |
| Model (Bedrock, pinned) | External | module-02 api, allowed_model | Reached over the private VPC endpoint |
| Agent planner and goal | Process | goal-lock (gate 2) | Standing objective; model-editable when OFF |
| lookup_account (MCP tool) | Process | tool-least-priv (gate 3) | Broad role reads the table when OFF |
| accounts | Data store | ACCOUNTS dict (stands in for the customer DB) | Includes admin api_key |
| send_email (MCP tool) | Process | hitl-approval (gate 4) | External send with no human when OFF |
| External recipient | External | billing-audit@external-domain.com | The exfiltration destination |
| Agent trace | Data store | trace[] | Always written |
| SOC alert path | Process | run-audit (gate 5), metric filter, alarm | Empty when OFF |
| Human approver | External | HITL queue | Only exists when gate 4 is ON |
| Cloud foundation | Data store and control plane | module-01 | Pinned hardened; S3, KMS, IAM, CloudTrail, flow logs |

Boundaries to number:

1. Customer document to ingest: the untrusted document boundary. The whole capstone is about this one.
2. Extracted text to model context: the instruction-versus-data boundary.
3. Model output to agent control state: the goal boundary.
4. Agent to tools: the authority boundary. Each tool call is a privilege decision.
5. Tool to data store: the scope boundary (one record or the table).
6. Tool to external world: the irreversible-action boundary.
7. Agent trace to SOC: the detection boundary (logged versus known).
8. Workload to provider: the model supply boundary.

## The asset register

Threats are only worth scoring against something worth protecting. List the assets, rank them, and the ranking becomes the "crown jewels" factor in Week 5. For both systems:

| Asset | System | Why it matters | Rank |
|---|---|---|---|
| Customer accounts and PII | Both | Regulatory exposure, reputation; the capstone table includes an admin credential | 1 |
| Provider API key | WS | Spend, and access to the model account | 2 |
| Pricing data (widgets.price) | WS | Direct financial loss when steered | 2 |
| Admin credentials and the admin plane | WS | Full control of the store | 1 |
| Agent objective and tool authority | CAP | Whoever holds these holds the agent | 1 |
| Audit trail and SOC path | Both | Without it, nothing else is provable | 2 |
| Cloud foundation (KMS, CloudTrail, S3) | CAP | Inherited; verified not assumed | 2 |
| Availability of the storefront and the agent | Both | Revenue and SLA | 3 |

## The MAESTRO layer map

For every AI component, place it on the seven layers. This is the single most useful table in the engagement for a reader who has not heard of MAESTRO: it shows them where the AI-specific risk physically lives.

| Layer | Widget Store | Capstone agent |
|---|---|---|
| L1 Foundation model | Stubbed model; SYSTEM_PROMPT with the key inside it | Bedrock model pinned by allowed_model |
| L2 Data operations | Catalog read by the assistant; no RAG, no memory | Ticket ingest (txt, pdf extraction); accounts store |
| L3 Agent frameworks | ask() route, DISCOUNT: parser, assistant role (hardened) | Agent loop, goal, lookup_account and send_email over MCP |
| L4 Deployment and infrastructure | Flask process, SQLite, debug mode, no WAF | AWS foundation, VPC endpoint, IAM roles, Terraform switches |
| L5 Evaluation and observability | None (weak); audit.py (hardened) | Agent trace; run-audit metric filter and alarm |
| L6 Security and compliance | appscan gate; the control map in the hardened prompt | posture.json as the contract; the green wall; the five switches |
| L7 Agent ecosystem | Single assistant; browser as the only peer | External email domain; human approver; the ticket filer |

Two observations the map makes obvious that a flat list would hide. The Widget Store has almost nothing at L5 and L6 in its weak build, which is why every attack on it is silent and why the scanner gate matters so much. The capstone's L6 is unusually strong for a lab, because posture.json forces the declared and deployed state to be the same file; that strength is also where CAP-09 lives, because nothing watches the file.

## The lab for this lesson

1. Draw both level 1 DFDs. Any tool is fine; the report template accepts an image. Number the boundary-crossing flows exactly as above so the register can reference them.
2. Draw the level 2 DFD for the capstone agent loop: ticket text in, model call, goal, tool selection, tool call, action, trace. Mark which of the five gates sits on which arrow.
3. Fill the Assets sheet in the workbook. Rank honestly; the rank feeds the priority order in Week 5 and you will have to defend it on the call.
4. Fill the MAESTRO map in section 5 of the report. One line per cell. If a cell is empty for a system, write "none" and say in a sentence why that is itself a finding or a non-issue.

> **THE STANDARD** A reviewer should be able to pick any register row in Week 2 and point to the element and the flow on your diagram that it belongs to. If they cannot, the row is floating, and floating rows are the ones that turn out to be wrong.

## What you can now do

You can decompose a web application and an agentic AI system into DFD elements and trust boundaries, rank their assets, and place every AI component on the seven MAESTRO layers. You have the drawings that STRIDE runs against. Next lesson you run it.
