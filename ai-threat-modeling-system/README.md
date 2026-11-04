# The AI Threat Modeling System

A Full Edition add-on to the Cloud and AI Security Engineer course. It teaches
threat modeling of cloud and AI systems as one repeatable engagement: STRIDE on
the cloud, API, and application tiers; CSA MAESTRO with STRIDE per layer on the
model, data, agent, and ecosystem tiers; cross-layer attack chains; evidence
collection; CVSS v4.0 with OWASP Risk Rating and a 5x5 matrix; a consulting-grade
report; a remediation roadmap; execution; retest; and the client readout. The
worked targets are the two systems already in this repo: the Widget Store and the
agentic support agent capstone.

## Deliverables (dist/)

- `AI-Threat-Modeling-System.pdf` — the 93-page method, in the Full Edition house style.
- `HWZ-Assessment-Report-Template.docx` — the consulting report template.
- `HWZ-Threat-Register-and-Risk-Workbook.xlsx` — the scored register and risk workbook, with the formulas live.

## Sources

- `chapters/00-front.md` through `chapters/16-grading-portfolio-ci.md` — the chapters.
- `register.py` — the single source of truth: the scored register, the verified controls, and the attack chains. Change a number here and every deliverable follows.
- `crosswalk.py` — NIST SP 800-53 Rev 5, CIS v8, and NIST AI RMF mappings per row.
- `build_addendum_pdf.py` — the reportlab PDF builder (needs `fonts/` and `assets/`).
- `build_register_xlsx.py` — the openpyxl workbook builder.
- `build_report_docx.js` — the docx-js report builder.
- `fonts/` — Lato and JetBrains Mono (Google Fonts, OFL). `assets/` — the logo and author photo.

## Rebuild

```
pip install --break-system-packages cvss reportlab openpyxl
python3 register.py              # prints the scored register; sanity check
python3 build_addendum_pdf.py    # writes dist/AI-Threat-Modeling-System.pdf
python3 build_register_xlsx.py   # then recalculate the workbook in a spreadsheet app
node build_report_docx.js        # needs the docx npm package
```

## Scoring, as shipped

- OWASP factor average to matrix axis: under 2 = 1; 2 to under 4 = 2; 4 to under 6 = 3; 6 to under 7.5 = 4; 7.5 and up = 5.
- Matrix bands: 1 to 5 Low; 6 to 11 Medium; 12 to 19 High; 20 to 25 Critical.
- The matrix rating governs. CVSS base is reported as the technical severity. OWASP overall is shown for transparency.

Build it. Release it. Break it. Harden it. Assess it. Prove it holds.

© 2026 Vigilantia Technologies INC. "HackWithZach" is a trademark of Vigilantia Technologies INC.
