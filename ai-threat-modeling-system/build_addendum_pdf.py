#!/usr/bin/env python3
"""
build_addendum_pdf.py -- builds "The AI Threat Modeling System" in the house
style of the Cloud and AI Security Engineer Full Edition (Lato, letter,
red kicker, black table headers, red callouts, standard About and
Disclaimer pages).

Runs on Linux. Fonts expected under ./fonts (Lato-*.ttf, JetBrainsMono.ttf);
assets under ./assets (logo.jpg, zach.jpg). Chapters are markdown-lite files
under ./chapters, built in sorted order. The register appendix is generated
from register.py so the numbers in the book are the numbers in the workbook.

    python3 build_addendum_pdf.py            # writes dist/AI-Threat-Modeling-System.pdf
"""
from __future__ import annotations

import os
import re
import sys
import html
from datetime import date

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph,
                                Spacer, Table, TableStyle, PageBreak, Image,
                                KeepTogether, Flowable, NextPageTemplate,
                                ListFlowable, ListItem, CondPageBreak)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.platypus.flowables import HRFlowable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import register as R          # noqa: E402
from crosswalk import CROSSWALK  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FONTS = os.path.join(HERE, "fonts")
ASSETS = os.path.join(HERE, "assets")
CHAPTERS = os.path.join(HERE, "chapters")
OUT = os.path.join(HERE, "dist", "AI-Threat-Modeling-System.pdf")

# ---------------------------------------------------------------- palette
RED = colors.HexColor("#d7261d")
BLACK = colors.HexColor("#0b0b0b")
INK = colors.HexColor("#1a1a1a")
MUTED = colors.HexColor("#555555")
RULE = colors.HexColor("#d9d9d9")
ZEBRA = colors.HexColor("#f6f6f6")
CALLOUT_BG = colors.HexColor("#fdecee")
CODE_BG = colors.HexColor("#f3f3f3")
CREAM = colors.HexColor("#f8ebcb")
GREEN = colors.HexColor("#1f7a3a")
GREEN_BG = colors.HexColor("#e6f4ea")
RED_BG = colors.HexColor("#fde8e6")
WHITE = colors.white

# ---------------------------------------------------------------- fonts
for name, fn in [("Lato", "Lato-Regular.ttf"), ("Lato-Bold", "Lato-Bold.ttf"),
                 ("Lato-Italic", "Lato-Italic.ttf"), ("Lato-BoldItalic", "Lato-BoldItalic.ttf"),
                 ("Lato-Black", "Lato-Black.ttf"), ("Mono", "JetBrainsMono.ttf")]:
    pdfmetrics.registerFont(TTFont(name, os.path.join(FONTS, fn)))
pdfmetrics.registerFontFamily("Lato", normal="Lato", bold="Lato-Bold",
                              italic="Lato-Italic", boldItalic="Lato-BoldItalic")

PAGE_W, PAGE_H = letter
MARGIN = 0.95 * inch
CONTENT_W = PAGE_W - 2 * MARGIN

# ---------------------------------------------------------------- styles
def S(name, **kw):
    base = dict(fontName="Lato", fontSize=10.5, leading=15, textColor=INK, spaceAfter=7)
    base.update(kw)
    return ParagraphStyle(name, **base)

st = {
    "kicker": S("kicker", fontName="Lato-Bold", fontSize=10, leading=12, textColor=RED, spaceAfter=10),
    "title": S("title", fontName="Lato-Black", fontSize=26, leading=30, textColor=BLACK, spaceAfter=10),
    "summary": S("summary", fontSize=11, leading=16, textColor=INK, spaceAfter=14),
    "h2": S("h2", fontName="Lato-Bold", fontSize=15, leading=19, textColor=BLACK, spaceBefore=12, spaceAfter=6),
    "h3": S("h3", fontName="Lato-Bold", fontSize=11.5, leading=15, textColor=BLACK, spaceBefore=8, spaceAfter=4),
    "body": S("body"),
    "bullet": S("bullet", leftIndent=14, bulletIndent=2, spaceAfter=4),
    "cell": S("cell", fontSize=8.6, leading=11, spaceAfter=0),
    "cellb": S("cellb", fontName="Lato-Bold", fontSize=8.6, leading=11, spaceAfter=0, textColor=WHITE),
    "cells": S("cells", fontSize=7.2, leading=9, spaceAfter=0),
    "cellsb": S("cellsb", fontName="Lato-Bold", fontSize=7.2, leading=9, spaceAfter=0, textColor=WHITE),
    "code": S("code", fontName="Mono", fontSize=8.3, leading=11, spaceAfter=0),
    "callout_t": S("callout_t", fontName="Lato-Bold", fontSize=10.5, leading=13, textColor=RED, spaceAfter=3),
    "callout_b": S("callout_b", fontSize=10, leading=14, spaceAfter=0),
    "foot": S("foot", fontSize=7.5, leading=9.5, textColor=MUTED, spaceAfter=0),
    "endnote": S("endnote", fontName="Lato-Italic", fontSize=9, leading=12, textColor=MUTED, spaceAfter=4),
    "caption": S("caption", fontName="Lato-Italic", fontSize=9, leading=12, textColor=MUTED, spaceBefore=4, spaceAfter=12),
    "toc1": S("toc1", fontSize=10.5, leading=16, spaceAfter=0),
    "toc2": S("toc2", fontSize=9.5, leading=13, leftIndent=14, spaceAfter=0, textColor=MUTED),
    "cover_title": S("cover_title", fontName="Lato-Black", fontSize=34, leading=40, textColor=WHITE, alignment=TA_CENTER, spaceAfter=18),
    "cover_kicker": S("cover_kicker", fontName="Lato-Bold", fontSize=13, leading=16, textColor=RED, alignment=TA_CENTER, spaceAfter=14),
    "cover_sub": S("cover_sub", fontName="Lato-Bold", fontSize=12, leading=15, textColor=WHITE, alignment=TA_CENTER, spaceAfter=24),
    "cover_tag": S("cover_tag", fontSize=12, leading=15, textColor=WHITE, alignment=TA_CENTER, spaceAfter=0),
    "cover_small": S("cover_small", fontSize=9.5, leading=13, textColor=WHITE, alignment=TA_CENTER, spaceAfter=0),
    "cover_tiny": S("cover_tiny", fontSize=7.5, leading=10, textColor=colors.HexColor("#cfcfcf"), alignment=TA_CENTER, spaceAfter=0),
    "cover_red": S("cover_red", fontName="Lato-Bold", fontSize=9, leading=12, textColor=RED, alignment=TA_CENTER, spaceAfter=0),
}

# ---------------------------------------------------------------- inline markup
def inline(text: str) -> str:
    """markdown-lite inline -> reportlab paragraph markup."""
    t = html.escape(text, quote=False)
    t = re.sub(r"`([^`]+)`", lambda m: '<font face="Mono" size="8.6">%s</font>' % m.group(1), t)
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"<i>\1</i>", t)
    return t


def P(text, style="body"):
    return Paragraph(inline(text), st[style])


# ---------------------------------------------------------------- flowables
class Callout(Flowable):
    def __init__(self, title, body, width=CONTENT_W):
        super().__init__()
        self.title, self.body, self.w = title, body, width
        self.pad = 10
        self.tp = Paragraph(inline(title), st["callout_t"])
        self.bp = Paragraph(inline(body), st["callout_b"])

    def wrap(self, aw, ah):
        iw = self.w - 2 * self.pad - 6
        _, th = self.tp.wrap(iw, ah)
        _, bh = self.bp.wrap(iw, ah)
        self.h = th + bh + 2 * self.pad + 3
        return self.w, self.h + 8

    def draw(self):
        c = self.canv
        c.saveState()
        c.setFillColor(CALLOUT_BG)
        c.setStrokeColor(CALLOUT_BG)
        c.rect(0, 4, self.w, self.h, fill=1, stroke=0)
        c.setFillColor(RED)
        c.rect(0, 4, 4, self.h, fill=1, stroke=0)
        iw = self.w - 2 * self.pad - 6
        _, bh = self.bp.wrap(iw, 1000)
        _, th = self.tp.wrap(iw, 1000)
        self.tp.drawOn(c, self.pad + 6, 4 + self.h - self.pad - th)
        self.bp.drawOn(c, self.pad + 6, 4 + self.pad)
        c.restoreState()


class CodeBlock(Flowable):
    def __init__(self, lines, width=CONTENT_W):
        super().__init__()
        self.lines, self.w = lines, width
        self.paras = [Paragraph(html.escape(l) or "&nbsp;", st["code"]) for l in lines]

    def wrap(self, aw, ah):
        self.h = sum(p.wrap(self.w - 20, ah)[1] for p in self.paras) + 16
        return self.w, self.h + 8

    def draw(self):
        c = self.canv
        c.setFillColor(CODE_BG)
        c.rect(0, 4, self.w, self.h, fill=1, stroke=0)
        y = 4 + self.h - 8
        for p in self.paras:
            _, h = p.wrap(self.w - 20, 1000)
            y -= h
            p.drawOn(c, 10, y)


def table(rows, widths=None, small=False, header=True, zebra=True, align_left=True):
    cs, hs = ("cells", "cellsb") if small else ("cell", "cellb")
    data = []
    for i, row in enumerate(rows):
        if i == 0 and header:
            data.append([Paragraph(inline(str(x)), st[hs]) for x in row])
        else:
            data.append([Paragraph(inline(str(x)), st[cs]) for x in row])
    if widths is None:
        n = len(rows[0])
        hdr = [len(str(rows[0][j])) for j in range(n)]
        body_len = [max([len(str(r[j])) for r in rows[1:]] or [0]) for j in range(n)]
        lens = [max(hdr[j] + 3, min(body_len[j], 45)) for j in range(n)]
        tot = sum(lens)
        widths = [CONTENT_W * l / tot for l in lens]
        # no column narrower than the widest header word plus padding
        minw = [max(0.62 * inch, pdfmetrics.stringWidth(max(str(rows[0][j]).split(), key=len), "Lato-Bold", 8.6) + 12) for j in range(n)]
        fixed = sum(max(0, minw[j] - widths[j]) for j in range(n))
        if fixed > 0:
            flex = [j for j in range(n) if widths[j] > minw[j]]
            flex_tot = sum(widths[j] - minw[j] for j in flex)
            for j in range(n):
                if widths[j] < minw[j]:
                    widths[j] = minw[j]
                elif flex_tot > 0:
                    widths[j] -= fixed * (widths[j] - minw[j]) / flex_tot
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), BLACK),
                  ("LINEBELOW", (0, 0), (-1, 0), 1.2, RED)]
    if zebra:
        for i in range(1 if header else 0, len(data)):
            if (i - (1 if header else 0)) % 2 == 1:
                style.append(("BACKGROUND", (0, i), (-1, i), ZEBRA))
    t.setStyle(TableStyle(style))
    return t


# ---------------------------------------------------------------- figures
def _box(c, x, y, w, h, label, fill=WHITE, stroke=BLACK, tc=INK, fs=7.5, bold=False, radius=3):
    c.saveState()
    c.setFillColor(fill); c.setStrokeColor(stroke); c.setLineWidth(0.8)
    c.roundRect(x, y, w, h, radius, fill=1, stroke=1)
    c.setFillColor(tc)
    c.setFont("Lato-Bold" if bold else "Lato", fs)
    lines = label.split("\n")
    lh = fs + 2
    ty = y + h / 2 + (len(lines) - 1) * lh / 2 - fs * 0.35
    for ln in lines:
        c.drawCentredString(x + w / 2, ty, ln)
        ty -= lh
    c.restoreState()


def _arrow(c, x1, y1, x2, y2, color=BLACK, width=0.9, dashed=False):
    c.saveState()
    c.setStrokeColor(color); c.setFillColor(color); c.setLineWidth(width)
    if dashed:
        c.setDash(3, 2)
    c.line(x1, y1, x2, y2)
    import math
    ang = math.atan2(y2 - y1, x2 - x1)
    L = 5
    p = c.beginPath()
    p.moveTo(x2, y2)
    p.lineTo(x2 - L * math.cos(ang - 0.45), y2 - L * math.sin(ang - 0.45))
    p.lineTo(x2 - L * math.cos(ang + 0.45), y2 - L * math.sin(ang + 0.45))
    p.close()
    c.setDash()
    c.drawPath(p, fill=1, stroke=0)
    c.restoreState()


class Figure(Flowable):
    """A black-banner figure in the house style, drawn by a named painter."""
    def __init__(self, name, title, height, width=CONTENT_W):
        super().__init__()
        self.name, self.title, self.w, self.fh = name, title, width, height

    def wrap(self, aw, ah):
        return self.w, self.fh + 26

    def draw(self):
        c = self.canv
        # banner
        c.setFillColor(BLACK)
        c.rect(0, self.fh, self.w, 24, fill=1, stroke=0)
        c.setFillColor(WHITE); c.setFont("Lato-Bold", 10.5)
        c.drawString(10, self.fh + 8, self.title)
        c.setFillColor(RED); c.setFont("Lato-Bold", 8)
        c.drawRightString(self.w - 10, self.fh + 8.5, "HackWithZach")
        c.setFillColor(colors.HexColor("#fafafa"))
        c.rect(0, 0, self.w, self.fh, fill=1, stroke=0)
        getattr(self, "paint_" + self.name.replace("-", "_"))(c)

    # -- MAESTRO stack
    def paint_maestro_stack(self, c):
        layers = [("L7", "Agent ecosystem", "other agents, external services, humans in the loop, the ticket filer"),
                  ("L5", "Evaluation and observability", "agent trace, metric filter, alarm, selftests, green wall"),
                  ("L4", "Deployment and infrastructure", "AWS foundation, VPC endpoint, IAM, Flask process, secrets"),
                  ("L3", "Agent frameworks", "agent loop, goal, tool registry, MCP tools, output handling"),
                  ("L2", "Data operations", "ticket ingest, PDF extraction, catalog, accounts, (RAG, memory)"),
                  ("L1", "Foundation model", "Bedrock model pinned; the stubbed assistant; the system prompt")]
        x0, w, h, gap = 14, self.w - 150, 30, 6
        y = 14
        for code, name, detail in reversed(layers):
            c.setFillColor(WHITE); c.setStrokeColor(BLACK); c.setLineWidth(0.8)
            c.roundRect(x0, y, w, h, 3, fill=1, stroke=1)
            c.setFillColor(RED); c.setFont("Lato-Bold", 9)
            c.drawString(x0 + 8, y + 17, code)
            c.setFillColor(BLACK); c.setFont("Lato-Bold", 9)
            c.drawString(x0 + 30, y + 17, name)
            c.setFillColor(MUTED); c.setFont("Lato", 7.2)
            c.drawString(x0 + 30, y + 7, detail)
            y += h + gap
        # L6 vertical
        vx = x0 + w + 14
        c.setFillColor(BLACK)
        c.roundRect(vx, 14, 108, y - 14 - gap, 3, fill=1, stroke=0)
        c.setFillColor(RED); c.setFont("Lato-Bold", 9)
        c.drawString(vx + 8, y - gap - 18, "L6")
        c.setFillColor(WHITE); c.setFont("Lato-Bold", 8.5)
        c.drawString(vx + 8, y - gap - 32, "Security and")
        c.drawString(vx + 8, y - gap - 43, "compliance")
        c.setFont("Lato", 7)
        for i, ln in enumerate(["vertical layer:", "controls, posture,", "scanners, gates,", "crosswalks, evidence", "touching L1 to L7"]):
            c.drawString(vx + 8, y - gap - 62 - i * 10, ln)
        c.setFillColor(MUTED); c.setFont("Lato-Italic", 7.5)
        c.drawString(x0, 4, "Threats chain upward: L1/L2 entry, L3 authority, L4 reach, L7 effect, L5 whether anyone finds out.")

    # -- Widget Store DFD
    def paint_ws_dfd(self, c):
        W = self.w
        _box(c, 14, 150, 80, 34, "Customer /\nattacker browser", fill=CREAM, bold=True)
        _box(c, 150, 120, 150, 95, "", fill=WHITE)
        c.setFillColor(BLACK); c.setFont("Lato-Bold", 8); c.drawString(156, 204, "Storefront process (weak/app.py)")
        _box(c, 158, 160, 62, 24, "login, catalog,\ncart, checkout", fs=6.5)
        _box(c, 230, 160, 62, 24, "admin route\n(same process)", fs=6.5, fill=RED_BG)
        _box(c, 158, 128, 62, 24, "assistant\nask()", fs=6.5, fill=RED_BG)
        _box(c, 230, 128, 62, 24, "run_shell()\nexport", fs=6.5, fill=RED_BG)
        _box(c, 370, 160, 90, 30, "store.db\nusers, widgets, orders", fs=6.8)
        _box(c, 370, 118, 90, 30, "CARTS dict\n(keyed by ?user=)", fs=6.8)
        _box(c, 370, 60, 90, 30, "Provider API\n(stub, key in prompt)", fs=6.8, fill=CREAM)
        _box(c, 14, 60, 80, 34, "Page template\n(key in <script>)", fs=6.8)
        _arrow(c, 94, 167, 150, 167)
        c.setFillColor(RED); c.setFont("Lato-Bold", 7); c.drawString(98, 171, "1 ?user&role")
        _arrow(c, 300, 175, 370, 175); c.drawString(306, 179, "2 SQL by %s")
        _arrow(c, 300, 135, 370, 135); c.drawString(306, 139, "4 DISCOUNT: write")
        _arrow(c, 189, 128, 189, 100); _arrow(c, 189, 100, 94, 80); c.drawString(100, 88, "model text unescaped")
        _arrow(c, 260, 128, 260, 100); _arrow(c, 260, 100, 370, 75); c.drawString(262, 92, "3 prompt + user text")
        c.setStrokeColor(RED); c.setDash(4, 3); c.setLineWidth(0.9)
        c.line(122, 40, 122, 230); c.setDash()
        c.setFillColor(RED); c.setFont("Lato-Italic", 7)
        c.drawString(100, 32, "trust boundary: internet | application. No boundary exists between customer, admin, model and shell.")
        c.setFillColor(MUTED); c.setFont("Lato-Italic", 7.5)
        c.drawString(14, 8, "Numbered flows are the ones STRIDE walks first. Red fill = a process that holds authority it should not.")

    # -- Capstone DFD
    def paint_cap_dfd(self, c):
        _box(c, 14, 150, 72, 34, "Customer or\nattacker (ticket)", fill=CREAM, bold=True)
        _box(c, 110, 150, 70, 34, "Ingest + parse\n(.txt / pypdf)", fs=6.8)
        _box(c, 200, 150, 60, 34, "Gate 1\nguardrail", fs=6.8, fill=GREEN_BG, stroke=GREEN)
        _box(c, 280, 150, 70, 34, "Model\n(Bedrock, pinned)", fs=6.8, fill=CREAM)
        _box(c, 370, 150, 70, 34, "Planner + goal\nGate 2 goal-lock", fs=6.8, fill=GREEN_BG, stroke=GREEN)
        _box(c, 280, 80, 80, 34, "lookup_account\nGate 3 least-priv", fs=6.8, fill=GREEN_BG, stroke=GREEN)
        _box(c, 380, 80, 80, 34, "send_email\nGate 4 HITL", fs=6.8, fill=GREEN_BG, stroke=GREEN)
        _box(c, 180, 80, 70, 34, "accounts\n(incl. admin key)", fs=6.8)
        _box(c, 380, 20, 80, 30, "External recipient\nexternal-domain.com", fs=6.5, fill=CREAM)
        _box(c, 14, 80, 72, 34, "Agent trace\n(always written)", fs=6.8)
        _box(c, 14, 20, 72, 34, "SOC alert path\nGate 5 run-audit", fs=6.5, fill=GREEN_BG, stroke=GREEN)
        _box(c, 110, 20, 70, 30, "Human approver\n(when gate 4 on)", fs=6.5, fill=CREAM)
        _arrow(c, 86, 167, 110, 167); _arrow(c, 180, 167, 200, 167); _arrow(c, 260, 167, 280, 167)
        _arrow(c, 350, 167, 370, 167)
        _arrow(c, 405, 150, 340, 114); _arrow(c, 280, 97, 250, 97)
        _arrow(c, 405, 150, 420, 114); _arrow(c, 420, 80, 420, 50)
        _arrow(c, 340, 80, 86, 97, dashed=True); _arrow(c, 50, 80, 50, 54, dashed=True)
        _arrow(c, 420, 80, 180, 40, dashed=True)
        c.setFillColor(RED); c.setFont("Lato-Bold", 7)
        c.drawString(88, 172, "1"); c.drawString(262, 172, "2"); c.drawString(352, 172, "3")
        c.drawString(372, 126, "4"); c.drawString(255, 101, "5"); c.drawString(424, 60, "6"); c.drawString(54, 62, "7")
        c.setStrokeColor(RED); c.setDash(4, 3); c.line(98, 10, 98, 200); c.setDash()
        c.setFillColor(MUTED); c.setFont("Lato-Italic", 7.5)
        c.drawString(14, 4, "Green = the five Terraform switches, all OFF in baseline. Dashed = detection path. Numbers = trust boundaries from A02.")

    # -- Chain A
    def paint_chain_a(self, c):
        hops = [("L2", "Poisoned\nPDF ticket", "CAP-06"), ("L1", "Guardrail OFF\nreaches model", "CAP-01"),
                ("L3", "Goal replaced:\nexfiltrate", "CAP-02"), ("L3/L4", "Broad role\nreads table", "CAP-03"),
                ("L7", "send_email\nexternal", "CAP-04"), ("L5", "No alarm\nSOC silent", "CAP-05")]
        locks = ["Guardrail on\nextracted text", "Gate 1\nguardrail", "Gate 2\ngoal-lock", "Gate 3\ntool-least-priv",
                 "Gate 4\nhitl-approval", "Gate 5 run-audit\n(detects only)"]
        n = len(hops); bw = 70; gap = (self.w - 28 - n * bw) / (n - 1)
        c.setFillColor(RED); c.setFont("Lato-Bold", 8.5); c.drawString(14, 150, "NAKED: the chain completes in silence")
        c.setFillColor(GREEN); c.drawString(14, 72, "HARDENED: the lock at each hop, any one of which holds")
        for i, (layer, text, rid) in enumerate(hops):
            x = 14 + i * (bw + gap)
            _box(c, x, 100, bw, 40, text, fill=RED_BG, stroke=RED, fs=7, bold=True)
            c.setFillColor(RED); c.setFont("Lato-Bold", 7); c.drawString(x + 2, 143, layer)
            c.setFillColor(MUTED); c.setFont("Mono", 6.5); c.drawRightString(x + bw - 2, 143, rid)
            if i < n - 1:
                _arrow(c, x + bw, 120, x + bw + gap, 120, color=RED, width=1.2)
            fill = GREEN_BG if i < 5 else colors.HexColor("#eeeeee")
            _box(c, x, 26, bw, 36, locks[i], fill=fill, stroke=GREEN if i < 5 else MUTED, fs=6.8, bold=True)
            _arrow(c, x + bw / 2, 100, x + bw / 2, 64, color=GREEN if i < 5 else MUTED, dashed=True)
        c.setFillColor(MUTED); c.setFont("Lato-Italic", 7.5)
        c.drawString(14, 8, "Gates 1 to 4 each hold alone (end_to_end.py --prove-independence). Gate 5 is why you find out, not why it did not happen.")

    # -- heat map
    def paint_heatmap(self, c):
        rows = [r for r in R.REGISTER if r["kind"] == "Finding"] + R.CHAINS
        cells = {}
        for r in rows:
            cells.setdefault((r["mx_l"], r["mx_i"]), []).append(r["id"])
        x0, y0, cw, ch = 60, 28, 78, 36
        bandcol = {"Low": colors.HexColor("#f1f1f1"), "Medium": CREAM, "High": colors.HexColor("#f2a39c"), "Critical": RED}
        for li in range(1, 6):
            for ii in range(1, 6):
                score = li * ii
                band = R.matrix_rating(score)
                x = x0 + (ii - 1) * cw; y = y0 + (li - 1) * ch
                c.setFillColor(bandcol[band]); c.setStrokeColor(WHITE); c.setLineWidth(1)
                c.rect(x, y, cw, ch, fill=1, stroke=1)
                c.setFillColor(WHITE if band == "Critical" else MUTED); c.setFont("Lato", 6)
                c.drawString(x + 3, y + ch - 8, str(score))
                ids = cells.get((li, ii), [])
                c.setFillColor(WHITE if band == "Critical" else BLACK); c.setFont("Mono", 5.6)
                line, lines = "", []
                for i in ids:
                    cand = (line + " " + i).strip()
                    if c.stringWidth(cand, "Mono", 5.6) > cw - 6:
                        lines.append(line); line = i
                    else:
                        line = cand
                if line:
                    lines.append(line)
                for k, ln in enumerate(lines[:4]):
                    c.drawString(x + 3, y + ch - 18 - k * 7, ln)
        c.setFillColor(BLACK); c.setFont("Lato-Bold", 7.5)
        for ii in range(1, 6):
            c.drawCentredString(x0 + (ii - 1) * cw + cw / 2, y0 - 10, f"Impact {ii}")
        for li in range(1, 6):
            c.drawRightString(x0 - 6, y0 + (li - 1) * ch + ch / 2 - 3, f"Likelihood {li}")
        lx = x0 + 5 * cw + 12
        c.setFont("Lato-Bold", 7.5); c.drawString(lx, y0 + 5 * ch - 10, "Bands")
        for k, (b, col) in enumerate([("Critical 20-25", RED), ("High 12-19", bandcol["High"]), ("Medium 6-11", CREAM), ("Low 1-5", bandcol["Low"])]):
            c.setFillColor(col); c.rect(lx, y0 + 5 * ch - 28 - k * 16, 10, 10, fill=1, stroke=0)
            c.setFillColor(BLACK); c.setFont("Lato", 7); c.drawString(lx + 14, y0 + 5 * ch - 26 - k * 16, b)
        c.setFillColor(MUTED); c.setFont("Lato-Italic", 7.5)
        c.drawString(14, 6, "Every finding and chain, plotted from its OWASP factor averages by the published mapping. The top-right cell is the executive summary.")


FIGURES = {
    "maestro-stack": ("MAESTRO: Seven Layers, One Vertical", 250),
    "ws-dfd": ("Widget Store, Level 1 Data Flow", 240),
    "cap-dfd": ("Agentic Support Agent, Level 1 Data Flow", 210),
    "chain-a": ("Chain A: One Poisoned Ticket, Every Layer", 160),
    "heatmap": ("Risk Heat Map: 26 Findings, 3 Chains", 240),
}
FIG_CAPTIONS = {
    "maestro-stack": "Figure A.1: The MAESTRO reference architecture. L6 is vertical: it touches every other layer.",
    "ws-dfd": "Figure A.2: Widget Store level 1 DFD with the five boundary-crossing flows numbered.",
    "cap-dfd": "Figure A.3: The capstone agent level 1 DFD, gates marked, boundaries numbered.",
    "chain-a": "Figure A.4: Chain A as the executive summary carries it.",
    "heatmap": "Figure A.5: The heat map. Chains are plotted alongside findings.",
}


# ---------------------------------------------------------------- markdown-lite parser
def parse_chapter(path):
    """Returns (meta, flowables)."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    meta = {}
    i = 0
    while i < len(lines) and re.match(r"^(kicker|title|summary):", lines[i]):
        k, v = lines[i].split(":", 1)
        meta[k.strip()] = v.strip()
        i += 1
    flows = []
    para = []

    def flush():
        if para:
            flows.append(P(" ".join(para)))
            para.clear()

    while i < len(lines):
        ln = lines[i]
        if not ln.strip():
            flush(); i += 1; continue
        if ln.startswith("## "):
            flush(); flows.append(CondPageBreak(1.1 * inch)); flows.append(Paragraph(inline(ln[3:]), st["h2"])); i += 1; continue
        if ln.startswith("### "):
            flush(); flows.append(Paragraph(inline(ln[4:]), st["h3"])); i += 1; continue
        if ln.startswith("```"):
            flush(); code = []; i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                code.append(lines[i]); i += 1
            i += 1
            flows.append(CodeBlock(code)); flows.append(Spacer(1, 4)); continue
        if ln.startswith("> "):
            flush()
            m = re.match(r"^> \*\*(.+?)\*\*\s*(.*)$", ln)
            if m:
                flows.append(Callout(m.group(1), m.group(2)))
            else:
                flows.append(Callout("NOTE", ln[2:]))
            flows.append(Spacer(1, 4)); i += 1; continue
        if ln.startswith("[[figure:"):
            flush()
            name = ln[len("[[figure:"):-2]
            title, h = FIGURES[name]
            flows.append(KeepTogether([Figure(name, title, h), Paragraph(FIG_CAPTIONS[name], st["caption"])]))
            i += 1; continue
        if ln.startswith("|"):
            flush(); rows = []
            while i < len(lines) and lines[i].startswith("|"):
                cells = [c.strip() for c in re.split(r"\|(?=(?:[^`]*`[^`]*`)*[^`]*$)", lines[i].strip().strip("|"))]
                if not all(re.match(r"^:?-{2,}:?$", c) for c in cells):
                    rows.append(cells)
                i += 1
            flows.append(table(rows)); flows.append(Spacer(1, 8)); continue
        if re.match(r"^- ", ln):
            flush(); items = []
            while i < len(lines) and re.match(r"^- ", lines[i]):
                items.append(lines[i][2:]); i += 1
            flows.append(ListFlowable([ListItem(P(t, "bullet"), leftIndent=14) for t in items],
                                      bulletType="bullet", start="•", bulletFontName="Lato", bulletFontSize=9,
                                      leftIndent=14))
            flows.append(Spacer(1, 4)); continue
        if re.match(r"^\d+\. ", ln):
            flush(); items = []
            while i < len(lines) and re.match(r"^\d+\. ", lines[i]):
                items.append(re.sub(r"^\d+\. ", "", lines[i])); i += 1
            flows.append(ListFlowable([ListItem(P(t, "bullet"), leftIndent=16) for t in items],
                                      bulletType="1", bulletFontName="Lato-Bold", bulletFontSize=9.5,
                                      leftIndent=16, bulletFormat="%s."))
            flows.append(Spacer(1, 4)); continue
        para.append(ln.strip()); i += 1
    flush()
    return meta, flows


# ---------------------------------------------------------------- doc template
class Doc(BaseDocTemplate):
    def __init__(self, path, **kw):
        super().__init__(path, pagesize=letter, leftMargin=MARGIN, rightMargin=MARGIN,
                         topMargin=0.9 * inch, bottomMargin=0.95 * inch,
                         title="AI Threat Modeling System", author="Zach Marcy", **kw)
        frame = Frame(MARGIN, 0.95 * inch, CONTENT_W, PAGE_H - 0.9 * inch - 0.95 * inch, id="f",
                      leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
        cover = Frame(0.9 * inch, 0.7 * inch, PAGE_W - 1.8 * inch, PAGE_H - 1.4 * inch, id="c",
                      leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
        self.addPageTemplates([PageTemplate(id="Cover", frames=[cover], onPage=self.on_cover),
                               PageTemplate(id="Body", frames=[frame], onPage=self.on_body)])

    def on_cover(self, c, doc):
        c.saveState()
        c.setFillColor(BLACK); c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
        c.setFillColor(RED); c.rect(0, PAGE_H - 26, PAGE_W, 26, fill=1, stroke=0)
        c.restoreState()

    def on_body(self, c, doc):
        c.saveState()
        c.setStrokeColor(RED); c.setLineWidth(1.1)
        c.line(MARGIN, 0.72 * inch, PAGE_W - MARGIN, 0.72 * inch)
        c.setFillColor(MUTED); c.setFont("Lato", 7.5)
        c.drawString(MARGIN, 0.72 * inch - 12, "Cybersecurity Education That Gets You Hired, Promoted and Paid.")
        c.drawString(MARGIN, 0.72 * inch - 23, "© Vigilantia Technologies INC. ™ HackWithZach.")
        c.drawRightString(PAGE_W - MARGIN, 0.72 * inch - 12, str(doc.page))
        c.restoreState()

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph):
            s = flowable.style.name
            if s == "title":
                text = flowable.getPlainText()
                if text in ("About Zach.", "Table of Contents."):
                    return
                key = "t%d" % id(flowable)
                label = getattr(flowable, "_toc_label", text)
                self.canv.bookmarkPage(key)
                self.notify("TOCEntry", (0, label, self.page, key))
                self.canv.addOutlineEntry(label, key, 0, 0)
            elif s == "h2" and getattr(self, "_toc_h2", False):
                text = flowable.getPlainText()
                key = "h%d" % id(flowable)
                self.canv.bookmarkPage(key)
                self.notify("TOCEntry", (1, text, self.page, key))


# ---------------------------------------------------------------- front and back matter
DISCLAIMER = ("This book is for education. The attacks you will learn exist so you can defend against them. "
              "Run every exercise only in the isolated sandbox accounts and environments this course tells you to create, "
              "against systems you own. Attacking systems you do not own or do not have written authorization to test is illegal. "
              "Cloud services cost money and their pricing changes; the cost figures in this book reflect the author's own runs at the "
              "time of writing, and your bill is your responsibility, which is why every chapter insists on budget alarms and teardown. "
              "The tools, services, and techniques described here change quickly; verify against current documentation before relying "
              "on them in production. This book is provided as is, without warranty of any kind, and nothing in it is legal, financial, "
              "or career advice. No specific job outcome or salary is promised; the outcomes described are what the work makes possible, "
              "not a guarantee.")

ABOUT = [
    ("<b>Cybersecurity, Cloud &amp; AI Architect, Consultant, and Mentor. 20+ years in IT. 6 in cybersecurity.</b>"),
    ("I am Zach Marcy. Online I go by HackWithZach. I am a Cybersecurity Architect, Consultant, and Mentor with 20+ years of IT "
     "experience and 6 in cybersecurity. My day-to-day work is designing cloud environments that deploy and secure APIs and AI, "
     "and advising the teams that run them. HackWithZach is the project where I turn that work into education."),
    ("<b>Why HackWithZach exists.</b> Through content, courses, and community, I teach Cybersecurity, Cloud and AI Architecture, "
     "and Consulting. The mission is to lower the barrier to entry for aspiring security professionals while giving working "
     "professionals a structured path to specialize. Career switchers get a hands-on path in. Working engineers and architects "
     "get the framework to level up. Skills map to real job outcomes."),
    ("<b>How I teach.</b> Build it, release it, break it, harden it. I combine hands-on technical expertise with a creator's mindset. "
     "Every framework I publish comes from work I have actually done. Quality over quantity. Depth over noise. Real-world relevance "
     "above all else."),
    ("Cybersecurity Education That Gets You Hired, Promoted and Paid. That is the promise."),
]

GLOSSARY = [
    ("Acceptance criterion", "A yes-or-no test, with a named runner, that proves a remediation item is closed."),
    ("Agent", "A loop that reads input, plans, calls tools and acts. The capstone's support agent."),
    ("ATLAS", "MITRE's knowledge base of adversary techniques against AI and ML systems; the AI counterpart of ATT&CK."),
    ("Attack chain", "One attack traced across several layers or elements, with the control that breaks it named at each hop."),
    ("CVSS v4.0", "The Common Vulnerability Scoring System, version 4.0; technical severity of a vulnerability on a 0 to 10 scale."),
    ("DFD", "Data flow diagram: external entities, processes, data stores and the flows between them."),
    ("Evidence of absence", "Proof that a control does not exist (an empty log, a missing file), captured as evidence."),
    ("Goal lock", "Holding the agent's objective outside model-writable state so a model turn cannot replace it."),
    ("Guardrail", "A screen on model input or output; in the capstone, gate 1 on ingested text."),
    ("HITL", "Human in the loop: a person gates an irreversible action before it runs."),
    ("Indirect prompt injection", "An instruction hidden in content the model was asked to read (a document, a web page, a tool result)."),
    ("MAESTRO", "CSA's seven-layer threat modeling framework for agentic AI."),
    ("MCP", "Model Context Protocol: the interface through which the agent's tools are exposed and called."),
    ("OWASP Risk Rating", "OWASP's method of scoring sixteen likelihood and impact factors, 0 to 9 each, and combining them."),
    ("Posture", "The set of controls actually deployed, as opposed to declared; the capstone writes it to posture.json."),
    ("Residual risk", "The risk that remains after remediation, stated with its owner."),
    ("Retest", "Re-running the acceptance criteria for a known list of findings; not a new assessment."),
    ("Risk acceptance", "A named owner's recorded decision to carry a risk rather than fix it, with a review date."),
    ("STRIDE", "Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege."),
    ("Trust boundary", "A point where data changes hands between parties with different levels of trust."),
    ("Verified control", "A control that the assessor ran a test against, rather than read about."),
]


def cover():
    f = [Spacer(1, 0.9 * inch)]
    logo = Image(os.path.join(ASSETS, "logo.jpg"), width=1.6 * inch, height=1.6 * inch)
    logo.hAlign = "CENTER"
    f += [logo, Spacer(1, 0.6 * inch),
          Paragraph("Cloud and AI<br/>Security Engineer", st["cover_title"]),
          Paragraph("THE AI THREAT MODELING SYSTEM", st["cover_kicker"]),
          Paragraph("THREAT MODEL. SCORE. REPORT. REMEDIATE. PROVE.", st["cover_sub"]),
          Paragraph("STRIDE and MAESTRO on the systems you built, scored three ways,<br/>written up the way a client pays for it, and driven to closure.", st["cover_tag"]),
          Spacer(1, 0.3 * inch),
          Paragraph("FULL EDITION ONLY", st["cover_red"]),
          Spacer(1, 1.5 * inch),
          Paragraph("By Zach Marcy", st["cover_small"]),
          Paragraph("Cybersecurity Architect and Mentor", st["cover_small"]),
          Spacer(1, 0.6 * inch),
          Paragraph("© 2026 Vigilantia Technologies INC. All rights reserved.", st["cover_tiny"]),
          Paragraph("\"HackWithZach\" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.", st["cover_tiny"]),
          Spacer(1, 0.25 * inch),
          Paragraph("Cybersecurity Education That Gets You Hired, Promoted and Paid.", st["cover_red"]),
          NextPageTemplate("Body"), PageBreak()]
    return f


def title_page():
    return [Spacer(1, 1.6 * inch),
            Paragraph("Cloud and AI Security Engineer", S("tp1", fontName="Lato-Black", fontSize=22, leading=26, spaceAfter=4)),
            Paragraph("The AI Threat Modeling System. Full Edition.", S("tp2", fontName="Lato-Bold", fontSize=12, leading=16, textColor=RED, spaceAfter=18)),
            Paragraph("By Zach Marcy, Cybersecurity Architect and Mentor", st["body"]),
            Paragraph("Build it. Release it. Break it. Harden it. Assess it.", st["body"]),
            Paragraph("Cybersecurity Education That Gets You Hired, Promoted and Paid.", st["body"]),
            Spacer(1, 0.5 * inch),
            Paragraph("© 2026 Vigilantia Technologies INC. All rights reserved. “HackWithZach” and the HackWithZach logo are trademarks of Vigilantia Technologies INC.",
                      S("tp3", fontSize=8.5, leading=12, textColor=MUTED)),
            Spacer(1, 0.4 * inch),
            Paragraph("<b>Disclaimer.</b>", S("tp4", fontSize=9, leading=12, spaceAfter=2)),
            Paragraph(DISCLAIMER, S("tp5", fontSize=8.5, leading=12, textColor=INK)),
            PageBreak()]


def about_page():
    photo = Image(os.path.join(ASSETS, "zach.jpg"), width=2.0 * inch, height=3.58 * inch)
    text = [Paragraph(t, S("ab", fontSize=10, leading=14, spaceAfter=8)) for t in ABOUT]
    t = Table([[photo, text]], colWidths=[2.15 * inch, CONTENT_W - 2.15 * inch])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                           ("RIGHTPADDING", (0, 0), (0, 0), 12)]))
    return [Paragraph("ABOUT", st["kicker"]), Paragraph("About Zach.", st["title"]),
            Paragraph("Zach Marcy | Cybersecurity, Cloud &amp; AI Architect &amp; Consultant | Creator of HackWithZach",
                      S("ab2", fontName="Lato-Bold", fontSize=11, leading=14, textColor=RED, spaceAfter=14)),
            t, PageBreak()]


def toc_page():
    toc = TableOfContents()
    toc.levelStyles = [st["toc1"], st["toc2"]]
    toc.dotsMinLevel = 0
    return [Paragraph("CONTENTS", st["kicker"]), Paragraph("Table of Contents.", st["title"]), toc, PageBreak()]


def chapter_end():
    return [Spacer(1, 14),
            Paragraph("Build it. Release it. Break it. Harden it. Assess it. Prove it holds.", st["endnote"]),
            Paragraph("© 2026 Vigilantia Technologies INC. All rights reserved. \"HackWithZach\" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.", st["endnote"]),
            PageBreak()]


def appendix_register():
    f = [Paragraph("APPENDIX A", st["kicker"]), Paragraph("The Threat Register.", st["title"]),
         Paragraph("The answer key, generated from the same data file as the workbook. Three views of the same rows: identification, "
                   "scoring, and remediation. CVSS v4.0 base scores are computed from the vector; OWASP averages are computed from the "
                   "sixteen factors; matrix axes and ratings follow the published mapping in A10.", st["summary"])]
    rows = R.REGISTER
    # A.1 identification
    f.append(Paragraph("A.1 Identification and classification", st["h2"]))
    t1 = [["ID", "Threat", "System / component", "Layer", "STRIDE", "OWASP", "MITRE", "CWE"]]
    for r in rows:
        t1.append([r["id"], r["title"], f'{r["system"]}: {r["component"]}', r["maestro"], r["stride"], r["owasp"], r["mitre"], r["cwe"]])
    f.append(table(t1, widths=[0.5 * inch, 1.5 * inch, 1.35 * inch, 0.8 * inch, 0.75 * inch, 1.0 * inch, 0.95 * inch, 0.55 * inch], small=True))
    f.append(PageBreak())
    # A.2 scoring
    f.append(Paragraph("A.2 Scoring", st["h2"]))
    t2 = [["ID", "CVSS v4.0 vector", "CVSS-B", "OWASP L avg", "OWASP I avg", "OWASP overall", "Matrix L x I", "Rating", "Phase"]]
    for r in rows:
        if r["kind"] != "Finding":
            t2.append([r["id"], "verified control", "n/a", "n/a", "n/a", "n/a", "n/a", "Verified", "n/a"]); continue
        t2.append([r["id"], r["cvss_vector"] or "n/a: absent control or design threat",
                   f'{r["cvss_score"]} ({r["cvss_severity"]})' if r["cvss_score"] else "n/a",
                   f'{r["owasp_likelihood"]} ({r["owasp_l_level"]})', f'{r["owasp_impact"]} ({r["owasp_i_level"]})',
                   r["owasp_overall"], f'{r["mx_l"]} x {r["mx_i"]} = {r["mx_score"]}', r["risk_rating"], r["phase"]])
    for c in R.CHAINS:
        t2.append([c["id"], "n/a: chain", "n/a", f'{c["owasp_likelihood"]} ({c["owasp_l_level"]})', f'{c["owasp_impact"]} ({c["owasp_i_level"]})',
                   c["owasp_overall"], f'{c["mx_l"]} x {c["mx_i"]} = {c["mx_score"]}', c["risk_rating"], R.PHASE_BY_RATING[c["risk_rating"]]])
    f.append(table(t2, widths=[0.55 * inch, 1.9 * inch, 0.65 * inch, 0.7 * inch, 0.7 * inch, 0.65 * inch, 0.75 * inch, 0.6 * inch, 0.9 * inch], small=True))
    f.append(Spacer(1, 8))
    f.append(Paragraph("Likelihood factors in order: skill level, motive, opportunity, size, ease of discovery, ease of exploit, awareness, intrusion detection. "
                       "Impact factors: loss of confidentiality, integrity, availability, accountability; financial, reputation, non-compliance, privacy.", st["caption"]))
    t2b = [["ID", "Likelihood factors (0-9)", "Impact factors (0-9)"]]
    for r in rows:
        if r["kind"] == "Finding":
            t2b.append([r["id"], ", ".join(map(str, r["likelihood_factors"])), ", ".join(map(str, r["impact_factors"]))])
    for c in R.CHAINS:
        t2b.append([c["id"], ", ".join(map(str, c["likelihood_factors"])), ", ".join(map(str, c["impact_factors"]))])
    f.append(table(t2b, widths=[0.7 * inch, 2.85 * inch, 2.85 * inch], small=True))
    f.append(PageBreak())
    # A.3 evidence and remediation
    f.append(Paragraph("A.3 Evidence, control and verification", st["h2"]))
    t3 = [["ID", "Evidence", "Control", "Reference", "Owner / effort", "Verification"]]
    for r in rows:
        t3.append([r["id"], r["evidence"], r["control"], r["control_ref"], f'{r["owner"]} / {r["effort"]}', r["verify"]])
    f.append(table(t3, widths=[0.5 * inch, 1.75 * inch, 1.45 * inch, 1.05 * inch, 0.8 * inch, 1.05 * inch], small=True))
    f.append(PageBreak())
    # A.4 chains
    f.append(Paragraph("A.4 Attack chains", st["h2"]))
    for c in R.CHAINS:
        f.append(Paragraph(f'{c["id"]}: {c["name"]} ({c["system"]}). Rating {c["risk_rating"]}, matrix {c["mx_score"]}.', st["h3"]))
        tc = [["Hop", "Layer", "Row", "What happens"]]
        for i, (layer, rid, what) in enumerate(c["hops"], 1):
            tc.append([str(i), layer, rid, what])
        f.append(table(tc, widths=[0.4 * inch, 0.6 * inch, 0.65 * inch, 4.95 * inch], small=True))
        f.append(Paragraph(f'<b>MITRE:</b> {c["mitre"]}', st["cell"]))
        f.append(Paragraph(f'<b>What stops it:</b> {c["stops"]}', st["cell"]))
        f.append(Spacer(1, 10))
    return f + [PageBreak()]


def appendix_crosswalk():
    f = [Paragraph("APPENDIX B", st["kicker"]), Paragraph("Framework Crosswalk.", st["title"]),
         Paragraph("Every register row mapped to the control vocabularies an auditor asks about. NIST SP 800-53 Rev 5 controls, "
                   "CIS Controls v8 safeguards, and NIST AI RMF 1.0 functions (with the Generative AI Profile risk names) for the AI rows. "
                   "OWASP Top 10 web identifiers are 2021; the 2025 edition renumbers (Injection to A05, Security Misconfiguration to A02, "
                   "Software Supply Chain Failures new at A03); the CWE column is stable across both.", st["summary"])]
    t = [["ID", "OWASP", "MITRE", "CWE", "NIST SP 800-53 Rev 5", "CIS v8", "NIST AI RMF / GAI"]]
    for r in R.REGISTER:
        n, cis, ai = CROSSWALK[r["id"]]
        t.append([r["id"], r["owasp"], r["mitre"], r["cwe"], n, cis, ai])
    f.append(table(t, widths=[0.5 * inch, 1.15 * inch, 1.1 * inch, 0.6 * inch, 1.3 * inch, 0.85 * inch, 1.1 * inch], small=True))
    return f + [PageBreak()]


def glossary():
    f = [Paragraph("GLOSSARY", st["kicker"]), Paragraph("Terms Used in the System.", st["title"])]
    t = [["Term", "Meaning"]] + [[a, b] for a, b in GLOSSARY]
    f.append(table(t, widths=[1.6 * inch, CONTENT_W - 1.6 * inch]))
    f.append(Spacer(1, 16))
    f.append(Paragraph("GO DEEPER", st["kicker"]))
    f.append(Paragraph("Standards and references.", st["h2"]))
    refs = ["Cloud Security Alliance, MAESTRO: Agentic AI Threat Modeling Framework (2025), and the CSA AI Controls Matrix.",
            "CSA, Applying MAESTRO to Real-World Agentic AI Threat Models: From Framework to CI/CD Pipeline (February 2026).",
            "OWASP Top 10 (2021 and 2025 editions); OWASP Top 10 for LLM Applications (2025); OWASP Top 10 for Agentic Applications (2026 edition, published December 2025).",
            "OWASP Risk Rating Methodology; OWASP Web Security Testing Guide v4.2, Reporting.",
            "FIRST, Common Vulnerability Scoring System v4.0 Specification and User Guide.",
            "MITRE ATT&CK (Enterprise and Cloud matrices); MITRE ATLAS; MITRE D3FEND.",
            "NIST SP 800-30 Rev 1; NIST SP 800-115; NIST SP 800-53 Rev 5; NIST AI RMF 1.0 and NIST AI 600-1 (Generative AI Profile).",
            "ISO/IEC 27005; CIS Controls v8; Penetration Testing Execution Standard (PTES), Reporting; Threat Modeling Manifesto."]
    f.append(ListFlowable([ListItem(P(r, "bullet"), leftIndent=14) for r in refs], bulletType="bullet", start="•",
                          bulletFontName="Lato", bulletFontSize=9, leftIndent=14))
    return f


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    doc = Doc(OUT)
    story = cover() + title_page() + about_page() + toc_page()
    files = sorted(fn for fn in os.listdir(CHAPTERS) if fn.endswith(".md"))
    for fn in files:
        meta, flows = parse_chapter(os.path.join(CHAPTERS, fn))
        tp = Paragraph(meta.get("title", ""), st["title"])
        m = re.search(r"LESSON (A\d+)", meta.get("kicker", ""))
        if m:
            tp._toc_label = f'{m.group(1)}: {meta.get("title", "")}'
        story += [Paragraph(meta.get("kicker", ""), st["kicker"]), tp,
                  Paragraph(inline(meta.get("summary", "")), st["summary"])]
        story += flows
        story += chapter_end()
    story += appendix_register() + appendix_crosswalk() + glossary()
    doc.multiBuild(story)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
