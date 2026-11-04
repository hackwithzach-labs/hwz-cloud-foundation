// build_report_docx.js -- the HackWithZach Assessment Report template (Word).
// Consulting-grade structure from Lesson A11, finding shape from A12, roadmap
// and risk acceptance from A13, retest letter from A14. Guidance text is gray
// italic and is meant to be deleted as each section is filled.
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell,
  WidthType, AlignmentType, BorderStyle, ShadingType, PageBreak, LevelFormat,
  TableOfContents, Header, Footer, PageNumber, ImageRun,
} = require("docx");

const RED = "D7261D", BLACK = "0B0B0B", GRAY = "666666", ZEBRA = "F6F6F6", LIGHT = "FDECEE";
const FONT = "Arial";
const PAGE_W = 12240, MARG = 1296, CONTENT = PAGE_W - 2 * MARG; // 0.9in margins

const p = (text, opts = {}) => new Paragraph({
  spacing: { after: opts.after ?? 120, before: opts.before ?? 0 },
  alignment: opts.align,
  children: Array.isArray(text) ? text : [new TextRun({ text, font: FONT, size: opts.size ?? 20, bold: opts.bold, italics: opts.italics, color: opts.color })],
  ...(opts.extra || {}),
});
const g = (text) => p(text, { italics: true, color: GRAY, size: 18 });
const h1 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 160 }, children: [new TextRun({ text, font: FONT, size: 34, bold: true, color: BLACK })] });
const h2 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 240, after: 100 }, children: [new TextRun({ text, font: FONT, size: 26, bold: true, color: BLACK })] });
const h3 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_3, spacing: { before: 180, after: 80 }, children: [new TextRun({ text, font: FONT, size: 22, bold: true, color: RED })] });
const kicker = (text) => p(text, { bold: true, color: RED, size: 18, after: 60 });
const bullets = (items) => items.map((t) => new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 60 }, children: [new TextRun({ text: t, font: FONT, size: 20 })] }));
const numbered = (items, ref) => items.map((t) => new Paragraph({ numbering: { reference: ref, level: 0 }, spacing: { after: 60 }, children: [new TextRun({ text: t, font: FONT, size: 20 })] }));
const pb = () => new Paragraph({ children: [new PageBreak()] });
const rule = () => new Paragraph({ spacing: { after: 120 }, border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: RED, space: 1 } }, children: [] });

function cell(text, w, opts = {}) {
  const runs = (Array.isArray(text) ? text : [text]).map((t) => new TextRun({ text: String(t ?? ""), font: FONT, size: opts.size ?? 17, bold: opts.bold, color: opts.color, italics: opts.italics }));
  return new TableCell({
    width: { size: w, type: WidthType.DXA },
    shading: opts.fill ? { type: ShadingType.CLEAR, fill: opts.fill, color: "auto" } : undefined,
    margins: { top: 60, bottom: 60, left: 90, right: 90 },
    children: [new Paragraph({ spacing: { after: 0 }, children: runs })],
  });
}
function table(header, rows, widths) {
  const tot = widths.reduce((a, b) => a + b, 0);
  const ws = widths.map((w) => Math.round((w / tot) * CONTENT));
  const diff = CONTENT - ws.reduce((a, b) => a + b, 0); ws[ws.length - 1] += diff;
  const trs = [new TableRow({ tableHeader: true, children: header.map((h, i) => cell(h, ws[i], { bold: true, color: "FFFFFF", fill: BLACK })) })];
  rows.forEach((r, k) => trs.push(new TableRow({ children: r.map((c, i) => cell(c, ws[i], { fill: k % 2 ? ZEBRA : undefined, italics: typeof c === "string" && c.startsWith("[") })) })));
  return new Table({ width: { size: CONTENT, type: WidthType.DXA }, columnWidths: ws, rows: trs,
    borders: { top: { style: BorderStyle.NONE }, left: { style: BorderStyle.NONE }, right: { style: BorderStyle.NONE }, bottom: { style: BorderStyle.SINGLE, size: 4, color: "D9D9D9" }, insideH: { style: BorderStyle.SINGLE, size: 4, color: "D9D9D9" }, insideV: { style: BorderStyle.NONE } } });
}
const callout = (title, text) => new Table({ width: { size: CONTENT, type: WidthType.DXA }, columnWidths: [CONTENT],
  borders: { top: { style: BorderStyle.NONE }, bottom: { style: BorderStyle.NONE }, right: { style: BorderStyle.NONE }, left: { style: BorderStyle.SINGLE, size: 24, color: RED }, insideH: { style: BorderStyle.NONE }, insideV: { style: BorderStyle.NONE } },
  rows: [new TableRow({ children: [new TableCell({ width: { size: CONTENT, type: WidthType.DXA }, shading: { type: ShadingType.CLEAR, fill: LIGHT, color: "auto" }, margins: { top: 120, bottom: 120, left: 160, right: 160 },
    children: [p(title, { bold: true, color: RED, size: 20, after: 40 }), p(text, { size: 19, after: 0 })] })] })] });

// ---------------------------------------------------------------- finding block
function findingBlock(f) {
  const rows = [
    ["Rating", f.rating], ["System / component / layer", f.scl], ["Classification", f.cls],
    ["Summary", f.summary], ["Description", f.description], ["Evidence", f.evidence],
    ["Impact", f.impact], ["Likelihood", f.likelihood], ["Remediation", f.remediation],
    ["Verification", f.verification], ["Status", f.status],
  ];
  return [h3(`${f.id}. ${f.title}`), table(["Field", "Content"], rows, [22, 78]), p("", { after: 160 })];
}

const WS01 = {
  id: "WS-01", title: "The application builds SQL from user input; a crafted username signs in as any user and a crafted search reads any table",
  rating: "CRITICAL. OWASP RR Critical (likelihood 8.25, impact 7.75). CVSS-B 9.3 CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
  scl: "Widget Store (weak) / weak/app.py login(), catalog(), cart(), orders(), checkout() / MAESTRO L4",
  cls: "OWASP A03:2021 Injection; MITRE ATT&CK T1190 Exploit Public-Facing Application; CWE-89",
  summary: "The storefront assembles SQL statements by string formatting at four locations, so request input becomes part of the statement. Anyone on the internet can sign in without a password and read the full user table, including passwords, from the search box.",
  description: "The login handler builds SELECT * FROM users WHERE username = '%s' AND password = '%s' from the form fields. The catalog search builds a LIKE clause the same way, and the cart, orders and checkout handlers interpolate ids. SQLite's driver supports bound parameters, which the hardened build uses throughout; the weak build never calls them. The scanner reports sql-interpolation at lines 119, 132, 214 and 284.",
  evidence: "(1) POST /login with username ' OR '1'='1 and any password: 302 to /catalog?user=1&name=alice&role=user. File WS-01-01.txt. (2) GET /catalog?q=' UNION SELECT id, username, password, 1, 1 FROM users --: the catalog renders usernames and plaintext passwords. File WS-01-02.png. (3) appscan output, 00-baseline-appscan-weak.txt.",
  impact: "Full read of customer and credential data, write access through the same construction on the order insert, and the entry hop of Chain C, which ends with every account password on the admin page. For the business: a credential breach of every customer, reportable, from a form that needs no account.",
  likelihood: "No skill beyond a copied payload (automated tools exist), no access needed, anonymous internet, nothing logged. Every likelihood factor is at or near its maximum.",
  remediation: "Bound parameters on every statement. The hardened build is the reference; its queries can be lifted directly. Keep the WAF sql-injection rule in front as defense in depth, not as the fix. Effort S (1 to 2 days including review of every query). Do not escape input instead; it is the wrong control and the scanner will still fail the build.",
  verification: "appscan weak/app.py no longer reports sql-interpolation; the login bypass returns the wrong-password page; the bench 'Inject SQL in the search box' is refused.",
  status: "Open. Owner: App engineering. Target: P0, day 2.",
};
const BLANK = {
  id: "[ID]", title: "[Threat in one sentence: what an attacker can do, from where]",
  rating: "[Final matrix rating, bold]. OWASP RR [overall] (likelihood [avg], impact [avg]). CVSS-B [score] [vector, or 'n/a: absent control or design threat']",
  scl: "[System] / [file, function] / [MAESTRO layer]", cls: "[OWASP ID(s)]; [MITRE technique(s)]; [CWE]",
  summary: "[Two sentences: what is wrong, and the so-what in business language]",
  description: "[The mechanism, in enough detail that an engineer agrees; how it was found]",
  evidence: "[Reproduction steps, then evidence file references from the manifest, then a redacted excerpt or figure]",
  impact: "[What the attacker gains, walked to the business consequence; cross-reference the chain if a hop]",
  likelihood: "[The factors that drove it, in words: who, what access, how easy, would anyone notice]",
  remediation: "[The control, specific enough to start; reference implementation; effort; what not to do]",
  verification: "[The command or test that proves it closed]",
  status: "[Open / In progress / Remediated / Verified / Risk accepted, with date, owner, phase and target day]",
};

const logo = fs.readFileSync(path.join(__dirname, "assets", "logo.jpg"));

const children = [
  // ---------------------------------------------------------------- cover
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 1200, after: 300 }, children: [new ImageRun({ type: "jpg", data: logo, transformation: { width: 110, height: 110 } })] }),
  p("THREAT MODEL AND VALIDATION ASSESSMENT", { bold: true, color: RED, size: 22, align: AlignmentType.CENTER, after: 120 }),
  p("[Client name]", { bold: true, size: 40, align: AlignmentType.CENTER, after: 80 }),
  p("[System(s) assessed]", { size: 26, align: AlignmentType.CENTER, after: 400 }),
  p("Report version [1.0]  |  [Date]  |  Classification: CONFIDENTIAL", { size: 20, align: AlignmentType.CENTER, after: 80 }),
  p("Prepared by [Assessor name], [Title]  |  Reviewed by [Reviewer name]", { size: 20, align: AlignmentType.CENTER, after: 1200 }),
  g("This document contains credentials, exploit detail and references to customer data. Distribute only to the names in the document control table. Destroy per the evidence handling rules in section 3."),
  p("Template: HackWithZach Assessment Report, AI Threat Modeling System. (c) 2026 Vigilantia Technologies INC. HackWithZach is a trademark of Vigilantia Technologies INC.", { size: 16, color: GRAY, align: AlignmentType.CENTER }),
  pb(),

  // ---------------------------------------------------------------- document control
  kicker("SECTION 0"), h1("Document Control"),
  table(["Field", "Entry"], [["Title", "[Threat Model and Validation Assessment: system names]"], ["Client", "[Client]"], ["Systems", "[System 1]; [System 2]"], ["Commit hash", "[git rev-parse --short HEAD]"], ["Version", "[1.0]"], ["Issue date", "[Date]"], ["Author", "[Name, title]"], ["Reviewer (not the author)", "[Name, title, date signed]"], ["Classification", "CONFIDENTIAL"], ["Distribution", "[Named individuals only]"], ["Evidence pack location and retention", "[Location, access control, destruction date]"]], [30, 70]),
  p("", { after: 120 }),
  h2("Change log"),
  table(["Version", "Date", "Author", "Change"], [["0.1", "[date]", "[name]", "Draft for internal review"], ["1.0", "[date]", "[name]", "Issued after reviewer sign-off"], ["1.1", "[date]", "[name]", "Section 11 added after retest"]], [12, 18, 20, 50]),
  pb(),
  kicker("CONTENTS"), h1("Table of Contents"),
  new TableOfContents("Contents", { hyperlink: true, headingStyleRange: "1-2" }),
  g("Right-click and update field after filling the report."),
  pb(),

  // ---------------------------------------------------------------- 1 exec summary
  kicker("SECTION 1"), h1("Executive Summary"),
  g("One page plus two figures. Write it last, place it first. No framework names, no CVSS vectors, no file paths. Six sentences in this order; delete this guidance."),
  p("[1. What was assessed and when. One sentence with system names, dates and the commit hash.]"),
  p("[2. The overall picture. One sentence with the numbers: N findings and N chains; N Critical, N High, N Medium, N Low; N inherited controls verified.]"),
  p("[3. The three things that matter, each in business language. For the course systems: a support ticket with one hidden paragraph makes the agent email the customer table to an outside address and no alarm fires; a web form with no password needed shows every customer's password; neither system records anything, so none of it would be noticed.]"),
  p("[4. What you recommend. The P0 phase in one sentence.]"),
  p("[5. What you need. Owners named, a date for the readout, access for the retest.]"),
  p("[Figure 1: the primary attack chain as a picture.]", { italics: true, color: GRAY }),
  p("[Figure 2: the risk heat map.]", { italics: true, color: GRAY }),
  callout("THE STANDARD", "The executive summary is the only page most of the people who pay for the report will read. If the decision is not on it, the report did not deliver the decision."),
  pb(),

  // ---------------------------------------------------------------- 2 scope
  kicker("SECTION 2"), h1("Engagement Overview and Scope"),
  h2("2.1 Engagement"),
  table(["Field", "Entry"], [["Engagement type", "Threat model with validation (vulnerability assessment and targeted exploitation used to evidence findings)"], ["Dates", "[start] to [end]"], ["Team", "[names, roles]"], ["Client contacts", "[names, roles]"], ["Commit hash assessed", "[hash]"]], [30, 70]),
  h2("2.2 In scope"), ...bullets(["[System 1: components, hosts, ports, routes, data stores]", "[System 2: components, infrastructure, tools, control switches]", "[Inherited modules assessed for verification of controls]"]),
  h2("2.3 Out of scope"), ...bullets(["[The provider model beyond the way the system calls it]", "[Cloud control plane beyond the composed IaC]", "[Physical, social engineering against staff, DoS against the lab host]"]),
  h2("2.4 Assumptions"), ...bullets(["[The weak builds represent what would have been deployed without review]", "[The hardened builds are the client's remediation candidates, assessed as such]", "[All testing against systems the assessor owns, per the rules of engagement]"]),
  h2("2.5 Limitations"), ...bullets(["[Model call is a stub; prompt-handling findings are assessed on the code around the call]", "[The attack harness simulates the agent loop deterministically]", "[Any control that could not be verified is listed here and marked Unverified in the register]"]),
  g("Every limitation sentence reappears in the finding it affects. A reviewer who finds an undeclared limitation assumes you did not know about it."),
  pb(),

  // ---------------------------------------------------------------- 3 RoE
  kicker("SECTION 3"), h1("Rules of Engagement"),
  table(["Rule", "Entry"], [["Authorization", "[System owner name, assessor name, dates, written approval reference]"], ["Testing windows", "[When active testing may run]"], ["Allowed techniques", "[Scanning, manual review, exploitation on weak builds, no destructive payloads beyond X, no data leaving the host]"], ["Stop conditions", "[Real customer data found; active compromise found; a control would be degraded by the test]"], ["Evidence handling", "[Location, access control, naming convention ID-sequence, SHA-256 manifest, retention and destruction date]"], ["Communication", "[Who is told of a Critical the day it is confirmed; readout date]"]], [25, 75]),
  pb(),

  // ---------------------------------------------------------------- 4 methodology
  kicker("SECTION 4"), h1("Methodology"),
  g("State the method as numbered rules an auditor can check, not prose. These eleven are the house method; edit only if you actually did something different."),
  ...numbered([
    "Decomposition: level 1 data flow diagrams for each system, numbered trust boundaries, an asset register ranked 1 to 3, and a CSA MAESTRO seven-layer map for every AI component.",
    "Enumeration: STRIDE per element and per data flow on the application, API and cloud tiers; STRIDE per layer inside MAESTRO on the model, data, agent framework, deployment, observability, compliance and ecosystem layers.",
    "Consolidation: one register row per distinct threat (root cause), with multiple locations recorded in evidence; scanner output consolidated, never counted per occurrence.",
    "Validation: every threat validated by reproduction or by the system's own tooling, or explicitly marked 'Threat (not validated)'; evidence of absence captured for absent controls. Validation ratio for this engagement: [N of M].",
    "Vocabulary: OWASP Top 10 (2021; crosswalk to 2025 in Appendix C), OWASP LLM Top 10 (2025), OWASP Agentic Top 10 (2026 edition); MITRE ATT&CK and ATLAS; CWE.",
    "Technical severity: CVSS v4.0 base (CVSS-B) for every vulnerability, from the vector string; never assigned to absent controls, design threats or chains; never the final rating.",
    "Risk factors: OWASP Risk Rating Methodology, sixteen factors scored 0 to 9 with the published anchors, averaged; scored for every row and chain.",
    "Final rating: 5 x 5 matrix, axes derived from the factor averages by the published mapping (under 2 = 1; 2 to 4 = 2; 4 to 6 = 3; 6 to 7.5 = 4; 7.5 and above = 5); bands 1 to 5 Low, 6 to 11 Medium, 12 to 19 High, 20 to 25 Critical. Disagreements with CVSS or OWASP overall are explained in the finding, never hidden.",
    "Priority: rating band descending, then CVSS-B descending, then crown-jewel rank, then ID. Chains are scored as rows with likelihood from the easiest entry hop and impact from the full outcome.",
    "Remediation: phases P0 (0 to 7 days, Critical), P1 (8 to 30, High), P2 (31 to 90, Medium), P3 (91 to 180, Low); every item carries an owner, effort, dependencies and an acceptance criterion; items without an owner move to the risk acceptance register.",
    "Retest: acceptance criteria run as written by a named runner with a witness and saved output; no new testing; regression suite run afterwards; residual risk stated with its owner.",
  ], "rules"),
  h2("4.1 Standards this report is consistent with"),
  p("PTES (Reporting); OWASP Web Security Testing Guide (Reporting); NIST SP 800-115; NIST SP 800-30 Rev 1; NIST SP 800-53 Rev 5 (crosswalk); ISO/IEC 27005 (risk owner, risk acceptance); CIS Controls v8 (crosswalk); NIST AI RMF 1.0 and NIST AI 600-1 (AI rows); CSA MAESTRO and CSA AI Controls Matrix; Threat Modeling Manifesto (sections 5, 8, 10 and 11 answer its four questions in order). This report does not certify compliance with any of them."),
  pb(),

  // ---------------------------------------------------------------- 5 architecture
  kicker("SECTION 5"), h1("Architecture and Trust Boundaries"),
  h2("5.1 System 1: [name]"), g("[Level 1 DFD figure. Then the element table and the numbered boundary-crossing flows.]"),
  table(["Element", "Type", "Where", "Notes"], [["[Customer browser]", "External", "[n/a]", "[also the attacker]"], ["[Storefront]", "Process", "[file]", "[all routes in one process]"], ["[store.db]", "Data store", "[file]", "[tables]"]], [25, 15, 25, 35]),
  p("Boundary-crossing flows:", { bold: true, before: 120 }), ...numbered(["[Browser to storefront: every request, with identity and role in the query string]", "[Storefront to store.db: queries built by string formatting]", "[...]"], "flows1"),
  h2("5.2 System 2: [name]"), g("[Level 1 DFD, element table, numbered boundaries. Level 2 for the agent loop with the gates marked on the arrows.]"),
  h2("5.3 Asset register"),
  table(["Asset", "System", "Why it matters", "Rank"], [["[Customer accounts and PII]", "[Both]", "[Regulatory exposure, reputation]", "1"], ["[...]", "", "", ""]], [30, 15, 45, 10]),
  h2("5.4 MAESTRO layer map"),
  table(["Layer", "System 1", "System 2"], [["L1 Foundation model", "[...]", "[...]"], ["L2 Data operations", "[...]", "[...]"], ["L3 Agent frameworks", "[...]", "[...]"], ["L4 Deployment and infrastructure", "[...]", "[...]"], ["L5 Evaluation and observability", "[...]", "[...]"], ["L6 Security and compliance", "[...]", "[...]"], ["L7 Agent ecosystem", "[...]", "[...]"]], [30, 35, 35]),
  g("If a cell is empty for a system, write 'none' and say in a sentence why that is a finding or a non-issue."),
  pb(),

  // ---------------------------------------------------------------- 6 summary
  kicker("SECTION 6"), h1("Summary of Findings"),
  h2("6.1 Counts"),
  table(["", "Critical", "High", "Medium", "Low", "Total"], [["System 1", "[ ]", "[ ]", "[ ]", "[ ]", "[ ]"], ["System 2", "[ ]", "[ ]", "[ ]", "[ ]", "[ ]"], ["Chains", "[ ]", "[ ]", "[ ]", "[ ]", "[ ]"], ["Total", "[ ]", "[ ]", "[ ]", "[ ]", "[ ]"]], [25, 15, 15, 15, 15, 15]),
  p("", { after: 120 }),
  table(["MAESTRO layer", "Findings", "Of which Critical/High"], [["L1", "[ ]", "[ ]"], ["L2", "[ ]", "[ ]"], ["L3", "[ ]", "[ ]"], ["L4", "[ ]", "[ ]"], ["L5", "[ ]", "[ ]"], ["L6", "[ ]", "[ ]"], ["L7", "[ ]", "[ ]"]], [40, 30, 30]),
  h2("6.2 Priority order"), g("From the register's Priority rank column. Chains first when they outrank the rows."),
  table(["#", "ID", "Rating", "CVSS-B", "Title", "Phase"], [["1", "[CHAIN-A]", "Critical", "n/a", "[The poisoned ticket: document to exfiltration]", "P0"], ["2", "[WS-01]", "Critical", "9.3", "[SQL injection in login and catalog search]", "P0"], ["...", "", "", "", "", ""]], [5, 12, 12, 10, 49, 12]),
  h2("6.3 Verified controls"), g("One line per verified control with the command that verified it. See section 9 for residual risk."),
  pb(),

  // ---------------------------------------------------------------- 7 chains
  kicker("SECTION 7"), h1("Attack Chains"),
  g("One chain per subsection. Six paragraphs, one per hop in the order the attacker meets them, each ending with the register ID and the breaking control in bold. Then one paragraph on independence with the evidence file. Then the figure. Under 500 words per chain."),
  h2("7.1 [CHAIN-A: name]. Rating [Critical]."),
  table(["Hop", "Layer", "Row", "What happens", "What breaks it here"], [["1", "[L2]", "[CAP-06]", "[...]", "[...]"], ["2", "[L1]", "[CAP-01]", "[...]", "[...]"], ["...", "", "", "", ""]], [7, 10, 12, 41, 30]),
  p("[Narrative paragraphs.]"), p("[Independence: evidence file and what it shows. Say explicitly which controls are preventive and which are detective.]"),
  p("[Figure: the chain.]", { italics: true, color: GRAY }),
  h2("7.2 [CHAIN-B]"), h2("7.3 [CHAIN-C]"),
  pb(),

  // ---------------------------------------------------------------- 8 findings
  kicker("SECTION 8"), h1("Detailed Findings"),
  g("One subsection per finding, in priority order, in the fixed shape below. The first block is a worked example from the course answer key (Widget Store WS-01). The second is the blank shape. Copy the blank shape for every finding."),
  ...findingBlock(WS01),
  ...findingBlock(BLANK),
  callout("THE STANDARD", "A finding is done when an engineer who has never seen the system can reproduce it from the report, fix it from the remediation, and prove the fix from the verification, without asking you anything."),
  pb(),

  // ---------------------------------------------------------------- 9 verified and residual
  kicker("SECTION 9"), h1("Verified Controls and Residual Risk"),
  table(["ID", "Control", "How it was verified", "Residual risk (register row)"], [["[CAP-V1]", "[Cloud foundation pinned hardened]", "[module-01 scan PASS in the green wall, file CAP-V1-01.txt]", "[CAP-09 drift; CAP-08 model pin]"], ["[CAP-V2]", "[Private model path, scoped role]", "[module-02 selftest PASS]", "[CAP-08]"]], [10, 30, 35, 25]),
  g("Verified means you ran it. 'The Terraform says true' is a claim the client already made."),
  pb(),

  // ---------------------------------------------------------------- 10 roadmap
  kicker("SECTION 10"), h1("Remediation Roadmap"),
  h2("10.1 Phases"),
  table(["Phase", "Window", "Enters here", "Exit criterion"], [["P0 Immediate", "Days 0 to 7", "Every Critical, plus anything a Critical depends on", "Chains broken at every hop; scanners show no HIGH"], ["P1 Short term", "Days 8 to 30", "Every High", "Scanners PASS; retest of all P0 and P1"], ["P2 Medium term", "Days 31 to 90", "Every Medium; detection and drift controls", "SOC path proven; CI gates live"], ["P3 Long term", "Days 91 to 180", "Lows; design; continuous threat modeling", "Threat model re-run on the next release"]], [18, 17, 32, 33]),
  h2("10.2 Roadmap"), g("Export from the workbook's Roadmap sheet. Every row has an owner, effort, dependency, target day and acceptance criterion. Draw the two lanes (application team; SOC and platform)."),
  table(["Phase", "ID(s)", "Action", "Owner", "Effort", "Depends on", "Day", "Acceptance criterion"], [["P0", "[CAP-01..05]", "[Apply hardened.tfvars]", "[AI platform]", "XS", "[window]", "1", "[BLOCKED at gate 1; independence PASS; scan PASS]"], ["P0", "[WS-01]", "[Bound parameters]", "[App eng]", "S", "", "2", "[appscan clears; bypass fails]"], ["...", "", "", "", "", "", "", ""]], [7, 12, 24, 12, 7, 10, 6, 22]),
  h2("10.3 Dependencies"), g("[Figure: dependency graph. Table: item, depends on, why.]"),
  h2("10.4 Effort and cost"), p("[Total engineering days by phase and team; who estimated; the client's day rate if they supplied one.]"),
  h2("10.5 Risk acceptance register"),
  table(["ID", "Rating", "Compensating control", "Rationale", "Risk owner", "Assessor advice", "Review date", "Signature"], [["[CAP-08]", "Medium", "[Weekly posture scan]", "[Pin correct today]", "[Name, role]", "[Accept until day 60]", "[Day 60]", "[ ]"]], [9, 9, 17, 17, 13, 17, 9, 9]),
  callout("THE STANDARD", "A remediation item with no owner, no date and no acceptance test is a recommendation. The plan contains none of those."),
  pb(),

  // ---------------------------------------------------------------- 11 retest letter
  kicker("SECTION 11"), h1("Retest and Closure Letter"),
  g("Issued separately after remediation, to the same distribution. One to two pages. Export this section on its own."),
  table(["Field", "Entry"], [["Reference", "[Report title, version, date; commit hash retested; retest date and window]"], ["Scope of retest", "[IDs retested. No new testing was performed.]"], ["Runner and witness", "[names]"]], [25, 75]),
  h2("11.1 Results"),
  table(["ID", "Original rating", "Remediation applied", "Result", "Evidence file"], [["[WS-01]", "Critical", "[Bound parameters on all statements]", "[Verified]", "[RT-WS-01.txt]"], ["[CAP-08]", "Medium", "[Accepted with compensating control]", "[Risk accepted]", "[RA entry 1]"], ["...", "", "", "", ""]], [10, 15, 40, 15, 20]),
  h2("11.2 Summary counts"), p("[Of N findings: N Verified, N Open, N Partially remediated, N Risk accepted. Of N chains: broken at N hops each.]"),
  h2("11.3 Regression"), p("[Green wall, bench and selftest results after remediation, with files.]"),
  h2("11.4 Residual risk statement"), g("One paragraph the board can read. Every clause checkable against 11.1. Example:"),
  p("Following remediation and retest, all eight Critical and twelve of thirteen High findings are verified closed, and all three attack chains are broken at every preventive hop with independence confirmed. One Medium finding (CAP-08) is accepted by the AI platform owner with a weekly posture scan as compensating control and a review date of day 60. Residual risk is assessed as Low for both systems, subject to the P2 controls landing on schedule; until they land, the risk that a future change silently reopens a closed finding is Medium and is owned by the platform lead. No findings are open without an accepted owner.", { italics: true }),
  h2("11.5 Recommendations"), p("[Next cycle date; triggers that re-open the model; anything observed but out of scope.]"),
  h2("11.6 Sign-off"),
  table(["Role", "Name", "Signature", "Date"], [["Assessor", "[ ]", "", ""], ["Reviewer", "[ ]", "", ""], ["Client risk owner (acknowledging residual risk)", "[ ]", "", ""]], [40, 25, 20, 15]),
  pb(),

  // ---------------------------------------------------------------- appendices
  kicker("APPENDIX A"), h1("Threat Register"), g("Export the workbook's Register and Chains sheets. Every column. The report carries the snapshot at the issue date; the workbook is the living document."),
  kicker("APPENDIX B"), h1("Evidence Index"), g("The manifest verbatim: file, finding ID(s), description, SHA-256, target commit hash. The pack itself is delivered separately under the handling rules in section 3."),
  table(["File", "Finding(s)", "Description", "SHA-256"], [["[00-baseline-greenwall.txt]", "All", "[Green wall output]", "[hash]"], ["[WS-01-01.txt]", "WS-01", "[Login bypass request and response]", "[hash]"], ["...", "", "", ""]], [28, 14, 38, 20]),
  kicker("APPENDIX C"), h1("Framework Crosswalk"), g("Export the workbook's Crosswalk sheet: ID, OWASP, MITRE, CWE, NIST SP 800-53 Rev 5, CIS v8, NIST AI RMF. Note for clients on OWASP Top 10 2025: Injection is A05, Security Misconfiguration A02, Software Supply Chain Failures new at A03; the CWE column is stable across both editions."),
  kicker("APPENDIX D"), h1("Glossary"), g("Every term a non-specialist meets in sections 1 and 7: prompt injection, indirect prompt injection, agent, tool, MCP, guardrail, goal lock, human in the loop, exfiltration, posture, residual risk, risk acceptance."),
  p("", { after: 240 }), rule(),
  p("Build it. Release it. Break it. Harden it. Assess it. Prove it holds.", { italics: true, color: GRAY, size: 18 }),
  p("(c) 2026 Vigilantia Technologies INC. All rights reserved. \"HackWithZach\" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.", { italics: true, color: GRAY, size: 16 }),
];

const doc = new Document({
  creator: "HackWithZach", title: "Assessment Report Template",
  styles: { default: { document: { run: { font: FONT, size: 20 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { font: FONT, size: 34, bold: true, color: BLACK }, paragraph: { spacing: { before: 360, after: 160 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { font: FONT, size: 26, bold: true, color: BLACK }, paragraph: { spacing: { before: 240, after: 100 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true, run: { font: FONT, size: 22, bold: true, color: RED }, paragraph: { spacing: { before: 180, after: 80 }, outlineLevel: 2 } },
    ] },
  numbering: { config: [
    { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 270 } } } }] },
    { reference: "rules", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 360 } } } }] },
    { reference: "flows1", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 360 } } } }] },
  ] },
  sections: [{
    properties: { page: { size: { width: PAGE_W, height: 15840 }, margin: { top: 1296, bottom: 1296, left: MARG, right: MARG } } },
    headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: "CONFIDENTIAL  |  Threat Model and Validation Assessment  |  [Client]", font: FONT, size: 16, color: GRAY })] })] }) },
    footers: { default: new Footer({ children: [new Paragraph({ border: { top: { style: BorderStyle.SINGLE, size: 8, color: RED, space: 4 } }, children: [new TextRun({ text: "Cybersecurity Education That Gets You Hired, Promoted and Paid.  (c) Vigilantia Technologies INC.  HackWithZach.  Page ", font: FONT, size: 15, color: GRAY }), new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 15, color: GRAY })] })] }) },
    children,
  }],
});

const out = path.join(__dirname, "dist", "HWZ-Assessment-Report-Template.docx");
Packer.toBuffer(doc).then((buf) => { fs.writeFileSync(out, buf); console.log("wrote", out); });
