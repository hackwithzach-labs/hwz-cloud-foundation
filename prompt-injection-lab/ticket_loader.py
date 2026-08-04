"""
ticket_loader.py - load a support ticket from a .txt OR a .pdf file.

Why this exists: the scary version of prompt injection hides inside a document
your agent is asked to read. A PDF is the classic carrier. Same agent, same
attack, just delivered as an uploaded file instead of pasted text.

(c) 2026 Vigilantia Technologies INC. HackWithZach. Education/defense only.
"""
import sys


def load_ticket(path):
    if path.lower().endswith(".pdf"):
        import warnings
        warnings.filterwarnings("ignore")          # keep the terminal clean
        try:
            from pypdf import PdfReader
        except ImportError:
            sys.exit("Reading a .pdf ticket needs pypdf:  pip install pypdf")
        pages = PdfReader(path).pages
        return "\n".join((p.extract_text() or "") for p in pages).strip()
    return open(path, encoding="utf-8").read().strip()
