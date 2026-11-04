#!/usr/bin/env python3
"""build_register_xlsx.py -- the Threat Register and Risk Workbook template.

Sheets: README, Frameworks, Scoring, Assets, Register (answer key, live
formulas), Register (blank) for the student's own engagement, Chains, CVSS,
Crosswalk, Roadmap, Risk Acceptance, Retest. Every rating is a formula on
the sixteen OWASP factors; students type factors, never ratings.
"""
import os, sys
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.formatting.rule import CellIsRule, FormulaRule

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import register as R
from crosswalk import CROSSWALK

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist", "HWZ-Threat-Register-and-Risk-Workbook.xlsx")

FONT = "Arial"
HDR_FILL = PatternFill("solid", fgColor="0B0B0B")
HDR_FONT = Font(name=FONT, bold=True, color="FFFFFF", size=10)
RED_FILL = PatternFill("solid", fgColor="D7261D")
INPUT_FILL = PatternFill("solid", fgColor="FFF2CC")
NOTE_FONT = Font(name=FONT, italic=True, color="555555", size=9)
BODY = Font(name=FONT, size=10)
BOLD = Font(name=FONT, bold=True, size=10)
BLUE = Font(name=FONT, size=10, color="0000FF")
TITLE = Font(name=FONT, bold=True, size=14)
THIN = Side(style="thin", color="D9D9D9")
BORDER = Border(bottom=THIN)
WRAP = Alignment(wrap_text=True, vertical="top")

CRIT = PatternFill("solid", fgColor="D7261D"); HIGH = PatternFill("solid", fgColor="F2A39C")
MED = PatternFill("solid", fgColor="F8EBCB"); LOW = PatternFill("solid", fgColor="F1F1F1")


def header(ws, row, cols, widths=None):
    for j, c in enumerate(cols, 1):
        cell = ws.cell(row=row, column=j, value=c)
        cell.fill = HDR_FILL; cell.font = HDR_FONT; cell.alignment = WRAP
        if widths:
            ws.column_dimensions[get_column_letter(j)].width = widths[j - 1]
    ws.row_dimensions[row].height = 30


def title(ws, text, sub=None):
    ws["A1"] = text; ws["A1"].font = TITLE
    if sub:
        ws["A2"] = sub; ws["A2"].font = NOTE_FONT
    ws.freeze_panes = "A4"


def body(ws, r, c, v, font=BODY, fill=None):
    cell = ws.cell(row=r, column=c, value=v)
    cell.font = font; cell.alignment = WRAP; cell.border = BORDER
    if fill:
        cell.fill = fill
    return cell


wb = Workbook()

# ------------------------------------------------------------------ README
ws = wb.active; ws.title = "README"
title(ws, "HackWithZach Threat Register and Risk Workbook", "the AI Threat Modeling System. Full Edition. (c) 2026 Vigilantia Technologies INC. HackWithZach is a trademark of Vigilantia Technologies INC.")
lines = [
    ("How to use this workbook", BOLD),
    ("1. Read Frameworks and Scoring. Do not change them; they are the house method the report's methodology section cites.", BODY),
    ("2. Fill Assets (Week 1), then Register (blank) one row per threat (Weeks 2 to 4). Yellow cells are inputs. White cells are formulas: never type over them.", BODY),
    ("3. Score the sixteen OWASP factors (Week 5). The sheet derives averages, levels, matrix axes, score, rating, phase and priority rank. You cannot type a rating.", BODY),
    ("4. Paste the CVSS v4.0 vector and the base score from the FIRST calculator into the CVSS columns. CVSS is reported, never the final rating.", BODY),
    ("5. Fill Chains, Roadmap, Risk Acceptance and Retest as the lessons direct (Weeks 4, 7).", BODY),
    ("6. Register is the answer key for the two course systems. Compare your Register (blank) against it; the PDF Appendix A explains every number.", BODY),
    ("", BODY),
    ("Legend", BOLD),
    ("Yellow fill = you type here.  White = formula, do not edit.  Blue text = a hard-coded anchor from the OWASP methodology.", BODY),
    ("Register IDs are never renumbered after a report is issued; the client's tickets refer to them.", BODY),
    ("", BODY),
    ("Standards this workbook is consistent with", BOLD),
    ("OWASP Risk Rating Methodology; FIRST CVSS v4.0; NIST SP 800-30 Rev 1 (risk register); CSA MAESTRO (layers); OWASP Top 10 2021, LLM Top 10 2025, Agentic Top 10 2026; MITRE ATT&CK and ATLAS; NIST SP 800-53 Rev 5; CIS Controls v8; NIST AI RMF 1.0.", BODY),
]
for i, (t, f) in enumerate(lines, 4):
    c = ws.cell(row=i, column=1, value=t); c.font = f; c.alignment = WRAP
ws.column_dimensions["A"].width = 120
ws.cell(row=6, column=1).fill = INPUT_FILL

# ------------------------------------------------------------------ Frameworks
ws = wb.create_sheet("Frameworks")
title(ws, "The framework stack and the one job each does", "From Lesson A01. Using a framework for a job that is not its own is the most common way an assessment loses credibility.")
header(ws, 4, ["Framework", "Job in this engagement", "Not its job", "Where in the workbook"], [26, 60, 40, 30])
rows = [
    ("STRIDE", "Enumerate threats per element and data flow on cloud, API and application tiers; and per layer inside MAESTRO", "Scoring, prioritization", "Register: STRIDE column"),
    ("CSA MAESTRO", "Decompose the AI system into seven layers; organize AI threats by layer; trace cross-layer chains", "Replacing STRIDE; it is a map, not an enumeration engine", "Register: MAESTRO layer; Chains sheet"),
    ("OWASP Top 10 (2021), LLM Top 10 (2025), Agentic Top 10 (2026)", "Name the class of weakness in a vocabulary the client's auditor trusts", "Completeness; a Top 10 is a floor", "Register: OWASP column; Crosswalk"),
    ("MITRE ATT&CK and ATLAS", "Name the attacker technique; tie each control to the step it breaks and each detection to its telemetry", "Scoring", "Register: MITRE column"),
    ("CVSS v4.0", "Technical severity of a vulnerability for interchange with the client's tooling", "Design threats, business impact, final priority", "Register and CVSS sheet"),
    ("OWASP Risk Rating", "Structured, defensible likelihood and impact factors for every row and chain", "A final verdict on its own", "Register: 16 factor columns"),
    ("5 x 5 matrix", "The one rating the executive summary reports and the roadmap is sorted by", "Replacing the factors that justify it", "Register: Matrix L, I, score, rating"),
]
for i, r in enumerate(rows, 5):
    for j, v in enumerate(r, 1):
        body(ws, i, j, v)

# ------------------------------------------------------------------ Scoring
ws = wb.create_sheet("Scoring")
title(ws, "Scoring rules: OWASP Risk Rating anchors and the house matrix mapping", "From Lessons A09 and A10. Blue values are the OWASP methodology's anchors; the mapping table is the house rule cited in the report methodology.")
header(ws, 4, ["Likelihood factor", "0-9 anchors"], [28, 90])
L_ANCH = [
    ("Skill level", "1 security penetration skills, 3 network and programming, 5 advanced computer user, 6 some technical skills, 9 no technical skills"),
    ("Motive", "1 low or no reward, 4 possible reward, 9 high reward"),
    ("Opportunity", "0 full access or expensive resources required, 4 special access or resources, 7 some access, 9 no access or resources required"),
    ("Size", "2 developers or system administrators, 4 intranet users, 5 partners, 6 authenticated users, 9 anonymous internet users"),
    ("Ease of discovery", "1 practically impossible, 3 difficult, 7 easy, 9 automated tools available"),
    ("Ease of exploit", "1 theoretical, 3 difficult, 5 easy, 9 automated tools available"),
    ("Awareness", "1 unknown, 4 hidden, 6 obvious, 9 public knowledge"),
    ("Intrusion detection", "1 active detection in application, 3 logged and reviewed, 8 logged without review, 9 not logged"),
]
for i, (a, b) in enumerate(L_ANCH, 5):
    body(ws, i, 1, a, BOLD); body(ws, i, 2, b, BLUE)
header(ws, 14, ["Impact factor", "0-9 anchors"])
I_ANCH = [
    ("Loss of confidentiality", "2 minimal non-sensitive data, 6 minimal critical or extensive non-sensitive, 7 extensive critical data, 9 all data"),
    ("Loss of integrity", "1 minimal slightly corrupt, 3 minimal seriously corrupt, 5 extensive slightly corrupt, 7 extensive seriously corrupt, 9 all data totally corrupt"),
    ("Loss of availability", "1 minimal secondary services, 5 minimal primary or extensive secondary, 7 extensive primary services, 9 all services"),
    ("Loss of accountability", "1 fully traceable, 7 possibly traceable, 9 completely anonymous"),
    ("Financial damage", "1 less than the cost to fix, 3 minor effect on annual profit, 7 significant effect, 9 bankruptcy"),
    ("Reputation damage", "1 minimal damage, 4 loss of major accounts, 5 loss of goodwill, 9 brand damage"),
    ("Non-compliance", "2 minor violation, 5 clear violation, 7 high-profile violation"),
    ("Privacy violation", "3 one individual, 5 hundreds of people, 7 thousands of people, 9 millions of people"),
]
for i, (a, b) in enumerate(I_ANCH, 15):
    body(ws, i, 1, a, BOLD); body(ws, i, 2, b, BLUE)
header(ws, 24, ["Rule", "Definition"])
RULES = [
    ("OWASP level", "Average of the eight factors: under 3 LOW; 3 to under 6 MEDIUM; 6 to 9 HIGH"),
    ("OWASP overall", "Likelihood level x impact level: LOW/LOW Note; MEDIUM/LOW or LOW/MEDIUM Low; HIGH/LOW, MEDIUM/MEDIUM, LOW/HIGH Medium; HIGH/MEDIUM, MEDIUM/HIGH High; HIGH/HIGH Critical"),
    ("Matrix axis from average", "under 2 = 1; 2 to under 4 = 2; 4 to under 6 = 3; 6 to under 7.5 = 4; 7.5 and above = 5. The top band is deliberately narrow."),
    ("Matrix rating from L x I", "1 to 5 Low; 6 to 11 Medium; 12 to 19 High; 20 to 25 Critical. Critical needs a 4x5 or 5x5."),
    ("Which score governs", "The matrix rating is the final rating. CVSS-B is reported as technical severity. OWASP overall is shown for transparency. Disagreements are explained in the report, never hidden."),
    ("Priority order", "Rating band descending, then CVSS-B descending, then crown-jewel rank from Assets, then ID."),
    ("Remediation phase", "Critical P0 Immediate (0-7 days); High P1 Short term (8-30); Medium P2 Medium term (31-90); Low/Note P3 Long term (91-180)."),
    ("CVSS v4.0", "Base vector and score from the FIRST calculator (first.org/cvss/calculator/4-0). Severity: Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0. Absent controls and design threats carry no vector."),
]
for i, (a, b) in enumerate(RULES, 25):
    body(ws, i, 1, a, BOLD); body(ws, i, 2, b)
# lookup table for OWASP overall used by formulas
ws["D4"] = "L level"; ws["E4"] = "I level"; ws["F4"] = "Overall"
for c in ("D4", "E4", "F4"):
    ws[c].font = HDR_FONT; ws[c].fill = HDR_FILL
for i, ((l, im), o) in enumerate(R.OWASP_OVERALL.items(), 5):
    ws.cell(row=i, column=4, value=l); ws.cell(row=i, column=5, value=im); ws.cell(row=i, column=6, value=o)
    ws.cell(row=i, column=7, value=f'=D{i}&"|"&E{i}')
ws["D14"] = "Key column G is used by the Register formulas; do not edit."; ws["D14"].font = NOTE_FONT
ws.column_dimensions["D"].width = 10; ws.column_dimensions["E"].width = 10; ws.column_dimensions["F"].width = 10; ws.column_dimensions["G"].width = 16

# ------------------------------------------------------------------ Assets
ws = wb.create_sheet("Assets")
title(ws, "Asset register", "Week 1, Lesson A02. Rank 1 = crown jewel. The rank is the tie-breaker in priority order.")
header(ws, 4, ["Asset", "System", "Why it matters", "Rank (1-3)", "Owner"], [36, 22, 60, 12, 20])
ASSETS = [
    ("Customer accounts and PII", "Both", "Regulatory exposure, reputation; the capstone table includes an admin credential", 1, ""),
    ("Admin credentials and the admin plane", "Widget Store", "Full control of the store", 1, ""),
    ("Agent objective and tool authority", "Capstone", "Whoever holds these holds the agent", 1, ""),
    ("Provider API key", "Widget Store", "Spend, and access to the model account", 2, ""),
    ("Pricing data (widgets.price)", "Widget Store", "Direct financial loss when steered", 2, ""),
    ("Audit trail and SOC path", "Both", "Without it, nothing else is provable", 2, ""),
    ("Cloud foundation (KMS, CloudTrail, S3)", "Capstone", "Inherited; verified not assumed", 2, ""),
    ("Availability of the storefront and the agent", "Both", "Revenue and SLA", 3, ""),
]
for i, r in enumerate(ASSETS, 5):
    for j, v in enumerate(r, 1):
        body(ws, i, j, v, fill=INPUT_FILL)
for i in range(13, 23):
    for j in range(1, 6):
        body(ws, i, j, None, fill=INPUT_FILL)

# ------------------------------------------------------------------ Register (shared layout)
COLS = ["ID", "Kind", "Status", "System", "Threat (title)", "Component", "DFD element", "Trust boundary", "MAESTRO layer", "STRIDE",
        "OWASP", "MITRE", "CWE", "Evidence", "CVSS v4.0 vector", "CVSS-B score", "CVSS severity",
        "Skill level", "Motive", "Opportunity", "Size", "Ease of discovery", "Ease of exploit", "Awareness", "Intrusion detection",
        "Loss of confidentiality", "Loss of integrity", "Loss of availability", "Loss of accountability", "Financial damage", "Reputation damage", "Non-compliance", "Privacy violation",
        "Likelihood avg", "L level", "Impact avg", "I level", "OWASP overall", "Matrix L", "Matrix I", "Matrix score", "RATING", "Phase", "Priority key", "Priority rank",
        "Control", "Control ref", "Owner", "Effort", "Verification", "Rationale / notes"]
WIDTHS = [8, 10, 10, 14, 36, 28, 24, 20, 18, 18, 26, 26, 12, 50, 34, 9, 10] + [7] * 16 + [9, 8, 9, 8, 10, 7, 7, 8, 10, 20, 9, 8, 40, 30, 16, 12, 36, 30]
INPUT_COLS = set(range(1, 16)) | {16} | set(range(18, 34)) | set(range(46, 52))
FIRST_FACTOR = 18  # R
LAST_L = 25        # Y
FIRST_I = 26       # Z
LAST_I = 33        # AG


def col(n):
    return get_column_letter(n)


def register_formulas(ws, r):
    L1, L2 = col(FIRST_FACTOR), col(LAST_L)
    I1, I2 = col(FIRST_I), col(LAST_I)
    ws.cell(row=r, column=17, value=f'=IF(P{r}="","n/a",IF(P{r}>=9,"Critical",IF(P{r}>=7,"High",IF(P{r}>=4,"Medium",IF(P{r}>0,"Low","None")))))')
    ws.cell(row=r, column=34, value=f'=IF(COUNT({L1}{r}:{L2}{r})<8,"",ROUND(AVERAGE({L1}{r}:{L2}{r}),2))')
    ws.cell(row=r, column=35, value=f'=IF(AH{r}="","",IF(AH{r}<3,"LOW",IF(AH{r}<6,"MEDIUM","HIGH")))')
    ws.cell(row=r, column=36, value=f'=IF(COUNT({I1}{r}:{I2}{r})<8,"",ROUND(AVERAGE({I1}{r}:{I2}{r}),2))')
    ws.cell(row=r, column=37, value=f'=IF(AJ{r}="","",IF(AJ{r}<3,"LOW",IF(AJ{r}<6,"MEDIUM","HIGH")))')
    ws.cell(row=r, column=38, value=f'=IF(OR(AI{r}="",AK{r}=""),"",INDEX(Scoring!$F$5:$F$13,MATCH(AI{r}&"|"&AK{r},Scoring!$G$5:$G$13,0)))')
    ws.cell(row=r, column=39, value=f'=IF(AH{r}="","",IF(AH{r}>=7.5,5,IF(AH{r}>=6,4,IF(AH{r}>=4,3,IF(AH{r}>=2,2,1)))))')
    ws.cell(row=r, column=40, value=f'=IF(AJ{r}="","",IF(AJ{r}>=7.5,5,IF(AJ{r}>=6,4,IF(AJ{r}>=4,3,IF(AJ{r}>=2,2,1)))))')
    ws.cell(row=r, column=41, value=f'=IF(OR(AM{r}="",AN{r}=""),"",AM{r}*AN{r})')
    ws.cell(row=r, column=42, value=f'=IF(AO{r}="","",IF(AO{r}>=20,"Critical",IF(AO{r}>=12,"High",IF(AO{r}>=6,"Medium","Low"))))')
    ws.cell(row=r, column=43, value=f'=IF(AP{r}="","",IF(AP{r}="Critical","P0 Immediate (0-7 days)",IF(AP{r}="High","P1 Short term (8-30 days)",IF(AP{r}="Medium","P2 Medium term (31-90 days)","P3 Long term (91-180 days)"))))')
    ws.cell(row=r, column=44, value=f'=IF(AP{r}="","",IF(AP{r}="Critical",4,IF(AP{r}="High",3,IF(AP{r}="Medium",2,1)))*100+IF(P{r}="",0,P{r}))')
    ws.cell(row=r, column=45, value=f'=IF(AR{r}="","",COUNTIF($AR$5:$AR$200,">"&AR{r})+1)')


def build_register(ws, rows, blank_rows=0):
    header(ws, 4, COLS, WIDTHS)
    r = 5
    for row in rows:
        vals = [row["id"], row["kind"], row["status"], row["system"], row["title"], row["component"], row["dfd_element"], row["boundary"],
                row["maestro"], row["stride"], row["owasp"], row["mitre"], row["cwe"], row["evidence"], row["cvss_vector"] or "", row["cvss_score"], None]
        lf = row["likelihood_factors"] or [None] * 8
        imf = row["impact_factors"] or [None] * 8
        vals += list(lf) + list(imf) + [None] * 12
        vals += [row["control"], row["control_ref"], row["owner"], row["effort"], row["verify"], ""]
        for j, v in enumerate(vals, 1):
            if j in INPUT_COLS:
                body(ws, r, j, v, fill=INPUT_FILL)
            else:
                body(ws, r, j, v)
        register_formulas(ws, r)
        r += 1
    for k in range(blank_rows):
        for j in range(1, len(COLS) + 1):
            body(ws, r, j, None, fill=INPUT_FILL if j in INPUT_COLS else None)
        register_formulas(ws, r)
        r += 1
    last = r - 1
    # conditional formatting on RATING
    rng = f"AP5:AP{last}"
    ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"Critical"'], fill=CRIT, font=Font(name=FONT, color="FFFFFF", bold=True)))
    ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"High"'], fill=HIGH))
    ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"Medium"'], fill=MED))
    ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"Low"'], fill=LOW))
    dv = DataValidation(type="whole", operator="between", formula1="0", formula2="9", allow_blank=True)
    dv.error = "OWASP factors are whole numbers 0 to 9."; ws.add_data_validation(dv)
    dv.add(f"{col(FIRST_FACTOR)}5:{col(LAST_I)}{last}")
    dvk = DataValidation(type="list", formula1='"Finding,Verified control,Threat (not validated)"', allow_blank=True); ws.add_data_validation(dvk); dvk.add(f"B5:B{last}")
    dvs = DataValidation(type="list", formula1='"Open,In progress,Remediated,Verified,Risk accepted"', allow_blank=True); ws.add_data_validation(dvs); dvs.add(f"C5:C{last}")
    ws.freeze_panes = "F5"
    ws.auto_filter.ref = f"A4:{col(len(COLS))}{last}"
    return last


ws = wb.create_sheet("Register")
title(ws, "Threat register: ANSWER KEY for the two course systems", "Yellow = inputs (as the answer key scored them). White = formulas. Change a factor and watch the rating move. Compare your own register against this one.")
build_register(ws, R.REGISTER)
ws2 = wb.create_sheet("Register (blank)")
title(ws2, "Threat register: YOUR engagement", "One row per distinct threat. Fill columns A to O and the 16 factors; everything else is derived. Row 5 is an example in the expected format; overwrite it.")
build_register(ws2, [R.by_id("WS-01")], blank_rows=49)

# ------------------------------------------------------------------ Chains
ws = wb.create_sheet("Chains")
title(ws, "Cross-layer attack chains", "Week 4, Lesson A07. One chain per block. Likelihood from the easiest entry hop; impact scored for the whole outcome.")
header(ws, 4, ["Chain ID", "Name", "System", "Hop", "Layer", "Register row", "What happens", "What breaks it here", "MITRE", "L factors (8)", "I factors (8)", "L avg", "I avg", "Matrix L", "Matrix I", "Score", "RATING"],
       [10, 34, 18, 6, 8, 12, 60, 40, 40, 22, 22, 8, 8, 8, 8, 8, 10])
r = 5
for c in R.CHAINS:
    first = r
    for i, (layer, rid, what) in enumerate(c["hops"], 1):
        vals = [c["id"] if i == 1 else "", c["name"] if i == 1 else "", c["system"] if i == 1 else "", i, layer, rid, what, "", c["mitre"] if i == 1 else ""]
        for j, v in enumerate(vals, 1):
            body(ws, r, j, v, fill=INPUT_FILL)
        r += 1
    body(ws, first, 10, ", ".join(map(str, c["likelihood_factors"])), fill=INPUT_FILL)
    body(ws, first, 11, ", ".join(map(str, c["impact_factors"])), fill=INPUT_FILL)
    body(ws, first, 12, c["owasp_likelihood"]); body(ws, first, 13, c["owasp_impact"])
    body(ws, first, 14, f"=IF(L{first}>=7.5,5,IF(L{first}>=6,4,IF(L{first}>=4,3,IF(L{first}>=2,2,1))))")
    body(ws, first, 15, f"=IF(M{first}>=7.5,5,IF(M{first}>=6,4,IF(M{first}>=4,3,IF(M{first}>=2,2,1))))")
    body(ws, first, 16, f"=N{first}*O{first}")
    body(ws, first, 17, f'=IF(P{first}>=20,"Critical",IF(P{first}>=12,"High",IF(P{first}>=6,"Medium","Low")))')
    body(ws, r, 7, "What stops it: " + c["stops"], NOTE_FONT); r += 2
ws.cell(row=r, column=1, value="Chain averages (L, M) are typed from the factor lists in J and K; the PDF Appendix A.4 shows the arithmetic.").font = NOTE_FONT

# ------------------------------------------------------------------ CVSS
ws = wb.create_sheet("CVSS")
title(ws, "CVSS v4.0 vectors and rationale", "Week 5, Lesson A09. Score at first.org/cvss/calculator/4-0 and paste vector and base score. One line of rationale per metric group, citing the evidence file.")
header(ws, 4, ["ID", "Vector (CVSS:4.0/...)", "Base score", "Severity", "Exploitability rationale (AV, AC, AT, PR, UI)", "Vulnerable system rationale (VC, VI, VA)", "Subsequent system rationale (SC, SI, SA)", "Why no vector (if absent control or design threat)"],
       [8, 44, 10, 10, 44, 40, 40, 40])
r = 5
for row in R.REGISTER:
    if row["kind"] != "Finding":
        continue
    body(ws, r, 1, row["id"]); body(ws, r, 2, row["cvss_vector"] or "", fill=INPUT_FILL); body(ws, r, 3, row["cvss_score"], fill=INPUT_FILL)
    body(ws, r, 4, f'=IF(C{r}="","n/a",IF(C{r}>=9,"Critical",IF(C{r}>=7,"High",IF(C{r}>=4,"Medium","Low"))))')
    for j in (5, 6, 7, 8):
        body(ws, r, j, "", fill=INPUT_FILL)
    if not row["cvss_vector"]:
        body(ws, r, 8, "Absent control or design threat: scored on OWASP factors only (A09).", fill=INPUT_FILL)
    r += 1

# ------------------------------------------------------------------ Crosswalk
ws = wb.create_sheet("Crosswalk")
title(ws, "Framework crosswalk (report Appendix C)", "Hand-mapped per row. OWASP web IDs are 2021; the CWE column is stable across the 2025 renumbering.")
header(ws, 4, ["ID", "Threat", "OWASP", "MITRE", "CWE", "NIST SP 800-53 Rev 5", "CIS Controls v8", "NIST AI RMF / GAI profile"], [8, 40, 30, 30, 12, 40, 26, 40])
for i, row in enumerate(R.REGISTER, 5):
    n, cis, ai = CROSSWALK[row["id"]]
    for j, v in enumerate([row["id"], row["title"], row["owasp"], row["mitre"], row["cwe"], n, cis, ai], 1):
        body(ws, i, j, v, fill=INPUT_FILL if j >= 6 else None)

# ------------------------------------------------------------------ Roadmap
ws = wb.create_sheet("Roadmap")
title(ws, "Remediation roadmap", "Week 7, Lesson A13. Phase comes from the rating; order within a phase from dependencies and effort. Owner and Day are agreed in the room.")
header(ws, 4, ["Phase", "Register ID(s)", "Action", "Owner", "Effort (XS/S/M/L/XL)", "Depends on", "Target day", "Acceptance criterion", "Runner", "Status", "Verified date"],
       [8, 16, 60, 20, 12, 14, 10, 50, 14, 12, 12])
ROAD = [
    ("P0", "CAP-01, 02, 03, 04, 05", "Apply hardened.tfvars; all five switches on", "AI platform", "XS", "Sandbox apply window", 1, "end_to_end.py on posture.json: BLOCKED at gate 1, SOC line; --prove-independence PASS; scan.py PASS"),
    ("P0", "WS-07", "Rotate leaked provider key; read from environment; refuse to start without it", "Platform", "S", "", 1, "Bench 'Find the API key' finds nothing; old key revoked in provider console"),
    ("P0", "WS-12", "debug=False; bind 127.0.0.1 behind the proxy", "Platform", "XS", "", 1, "appscan: debug-mode-on and binds-all-interfaces clear"),
    ("P0", "WS-01", "Bound parameters on every statement", "App engineering", "S", "", 2, "appscan sql-interpolation clears; login bypass returns wrong-password page"),
    ("P0", "WS-08", "Remove the shell sink; do the export in code", "App engineering", "S", "", 2, "appscan shell-from-request clears"),
    ("P0", "WS-02", "Signed session cookie; role from the database", "App engineering", "M", "WS-07", 5, "appscan identity-in-request clears; URL edits do not change identity"),
    ("P0", "WS-03", "Admin as a separate service, own login and cookie", "App engineering, Platform", "M", "WS-02", 7, "GET /admin on storefront is 404; admin.py refuses a customer session"),
    ("P0", "WS-10", "Hash passwords; force reset; never select the column", "App engineering", "S", "WS-03", 7, "users.password holds PBKDF2; admin page shows no password column"),
    ("P1", "WS-05, WS-11", "Assistant capability allow-list; reply as display text; reprice at checkout on admin plane", "App engineering, AI platform", "M", "WS-03", 12, "Bench 'Set the price with a sentence' refuses; 'Buy the catalog for nothing' charges list price"),
    ("P1", "WS-06", "Separate instruction and user channels; remove secret from prompt", "AI platform", "S", "WS-07", 10, "Extraction attempt returns a prompt with no secret"),
    ("P1", "WS-04", "Owner predicate on every order query", "App engineering", "S", "WS-02", 9, "Bench 'Read another customer's order' refused"),
    ("P1", "WS-09, WS-16", "Escape at render; CSP and headers; validators; WAF before every view", "App engineering", "M", "", 20, "appscan unescaped-output, no-waf, no-input-validation, no-security-headers clear"),
    ("P1", "WS-13, WS-14", "Login attempt counters; CSRF tokens; SameSite", "App engineering", "S", "WS-02", 15, "6th failed login within five minutes returns 429; POST without token returns 400"),
    ("P1", "WS-15", "Structured audit log; admin console tails it", "App engineering, SOC", "S", "", 14, "audit.log shows login, waf.block, checkout events; appscan no-audit-log clears"),
    ("P1", "CAP-06", "Guardrail on extracted text; render-vs-extract diff; ingest limits", "AI platform", "S", "CAP-01", 21, "Hidden-text ticket blocked at gate 1 and flagged"),
    ("P1", "CAP-07", "Approval UI shows recipient domain, record count, source paragraph; second approver for external", "Support ops, AI platform", "M", "CAP-04", 30, "Approver walkthrough: external recipient and count visible without expanding"),
    ("P2", "CAP-09", "CI terraform plan fails on drift; posture compared to live", "Platform", "S", "", 45, "tfvars edit without apply fails CI"),
    ("P2", "CAP-10", "Iteration cap, per-tool cost caps, per-run token budget", "AI platform", "S", "CAP-01", 45, "Looping ticket aborts at ceiling with audit event"),
    ("P2", "CAP-08", "Model ARN pinned as IAM resource; drift check; version on every call", "Cloud IAM", "S", "CAP-09", 60, "scan.py confirms pin; CloudTrail InvokeModel carries model ARN"),
    ("P2", "All", "appscan and end_to_end selftest in CI; HIGH fails the build", "Platform", "S", "WS-all", 60, "Branch reopening WS-01 fails CI (red run screenshot)"),
    ("P3", "All", "Re-run threat model on next feature; quarterly schedule; trigger list in SECURITY.md", "Security", "M", "P2 complete", 120, "Trigger list merged; next-cycle date set"),
]
for i, rr in enumerate(ROAD, 5):
    for j, v in enumerate(rr, 1):
        body(ws, i, j, v, fill=INPUT_FILL)
    body(ws, i, 9, "", fill=INPUT_FILL); body(ws, i, 10, "Open", fill=INPUT_FILL); body(ws, i, 11, "", fill=INPUT_FILL)
dv = DataValidation(type="list", formula1='"Open,In progress,Remediated,Verified,Failed retest,Risk accepted"', allow_blank=True); ws.add_data_validation(dv); dv.add("J5:J60")

# ------------------------------------------------------------------ Risk Acceptance
ws = wb.create_sheet("Risk Acceptance")
title(ws, "Risk acceptance register", "A named owner's recorded decision to carry a risk. The assessor records the advice given; the owner signs.")
header(ws, 4, ["Register ID", "Rating", "Compensating control", "Acceptance rationale", "Risk owner (named individual)", "Assessor advice", "Review date", "Signature / date"], [12, 10, 40, 50, 24, 40, 12, 20])
body(ws, 5, 1, "CAP-08", fill=INPUT_FILL); body(ws, 5, 2, "Medium", fill=INPUT_FILL)
body(ws, 5, 3, "Weekly posture scan (scan.py --posture) until the drift check lands in P2", fill=INPUT_FILL)
body(ws, 5, 4, "Model pin is correct today; drift is Low likelihood with weekly verification", fill=INPUT_FILL)
body(ws, 5, 5, "(name), AI platform lead", fill=INPUT_FILL); body(ws, 5, 6, "Accept with compensating control; close by day 60", fill=INPUT_FILL)
body(ws, 5, 7, "Day 60", fill=INPUT_FILL); body(ws, 5, 8, "", fill=INPUT_FILL)
for i in range(6, 16):
    for j in range(1, 9):
        body(ws, i, j, None, fill=INPUT_FILL)

# ------------------------------------------------------------------ Retest
ws = wb.create_sheet("Retest")
title(ws, "Retest results (feeds the retest letter)", "Week 7, Lesson A14. Run the acceptance criterion as written. Result is Verified, Open, Partially remediated, or Risk accepted. No new testing.")
header(ws, 4, ["Register ID", "Original rating", "Remediation applied (one line)", "Acceptance criterion", "Runner", "Witness", "Date", "Result", "Evidence file"], [12, 12, 50, 50, 14, 14, 12, 16, 24])
r = 5
for row in R.REGISTER:
    if row["kind"] != "Finding":
        continue
    body(ws, r, 1, row["id"]); body(ws, r, 2, f"=IFERROR(INDEX(Register!$AP$5:$AP$200,MATCH(A{r},Register!$A$5:$A$200,0)),\"\")")
    body(ws, r, 3, "", fill=INPUT_FILL); body(ws, r, 4, row["verify"], fill=INPUT_FILL)
    for j in (5, 6, 7, 8, 9):
        body(ws, r, j, "", fill=INPUT_FILL)
    r += 1
dv = DataValidation(type="list", formula1='"Verified,Open,Partially remediated,Risk accepted"', allow_blank=True); ws.add_data_validation(dv); dv.add(f"H5:H{r}")
r += 1
ws.cell(row=r, column=1, value="Summary").font = BOLD
ws.cell(row=r + 1, column=1, value="Verified"); ws.cell(row=r + 1, column=2, value=f'=COUNTIF(H5:H{r-2},"Verified")')
ws.cell(row=r + 2, column=1, value="Open"); ws.cell(row=r + 2, column=2, value=f'=COUNTIF(H5:H{r-2},"Open")')
ws.cell(row=r + 3, column=1, value="Partially remediated"); ws.cell(row=r + 3, column=2, value=f'=COUNTIF(H5:H{r-2},"Partially remediated")')
ws.cell(row=r + 4, column=1, value="Risk accepted"); ws.cell(row=r + 4, column=2, value=f'=COUNTIF(H5:H{r-2},"Risk accepted")')

for sheet in wb.worksheets:
    for row in sheet.iter_rows():
        for c in row:
            if c.font and c.font.name != FONT:
                c.font = Font(name=FONT, size=c.font.size or 10, bold=c.font.bold, italic=c.font.italic, color=c.font.color)

os.makedirs(os.path.dirname(OUT), exist_ok=True)
wb.save(OUT)
print("wrote", OUT)
