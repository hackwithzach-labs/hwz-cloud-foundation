#!/usr/bin/env python3
"""appscan.py -- the gate for generated application code.

scan.py reads a Terraform plan. This reads an application's source, because a
vibe-coded web app never produces a plan to scan. Same contract as every other
scanner in this course:

    one CHECKS table, every row carries its own severity, what it means, WHAT
    CLOSES IT and the framework mapping; a HIGH finding exits non-zero.

Run it:

    python3 appscan/appscan.py weak/app.py
    python3 appscan/appscan.py hardened/app.py
    python3 appscan/appscan.py weak/app.py --table      # the deck's table
    python3 appscan/appscan.py --selftest               # prove the gate works

WHY IT READS CODE AND NOT COMMENTS
Comments and docstrings are stripped before any pattern runs. A scanner that
greps raw text finds the word `subprocess` in a comment that says "never call
subprocess" and reports a gap that is not there. Both halves of this lab are
heavily commented, so a text-only scanner would score them almost the same.
That is not a detail. A gate you cannot trust gets switched off.
"""
import argparse
import ast
import io
import os
import re
import sys
import tokenize

HIGH, MED, LOW = "HIGH", "MEDIUM", "LOW"


# --------------------------------------------------------------------------
# Source views
# --------------------------------------------------------------------------
def code_only(src: str) -> str:
    """The source with comments and docstrings removed.

    Comment tokens are dropped outright. A string that forms an entire
    statement is a docstring or a block comment, so it is dropped too. Strings
    used as values stay, because a hardcoded key IS a value and the scanner has
    to be able to see it."""
    out = []
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except tokenize.TokenError:
        return src
    prev_end = (1, 0)
    at_stmt_start = True
    for tok in toks:
        if tok.type == tokenize.COMMENT:
            continue
        if tok.type == tokenize.STRING and at_stmt_start:
            continue  # docstring or block comment
        if tok.type in (tokenize.NEWLINE, tokenize.NL, tokenize.INDENT,
                        tokenize.DEDENT):
            at_stmt_start = True
        elif tok.type not in (tokenize.ENCODING,):
            at_stmt_start = False
        out.append(tok.string if tok.type != tokenize.NEWLINE else "\n")
        prev_end = tok.end
    return " ".join(out)


class Source:
    def __init__(self, path):
        self.path = path
        with open(path, "r", encoding="utf-8") as f:
            self.raw = f.read()
        self.code = code_only(self.raw)
        self.tree = ast.parse(self.raw, filename=path)
        self.calls = [n for n in ast.walk(self.tree) if isinstance(n, ast.Call)]

    def called(self, *names):
        """Every Call node whose callee ends in one of `names`."""
        hits = []
        for c in self.calls:
            f = c.func
            name = f.attr if isinstance(f, ast.Attribute) else \
                f.id if isinstance(f, ast.Name) else None
            if name in names:
                hits.append(c)
        return hits

    def has(self, pattern):
        return re.search(pattern, self.code, re.I | re.S) is not None

    def count(self, pattern):
        return len(re.findall(pattern, self.code, re.I | re.S))


# --------------------------------------------------------------------------
# The checks. One row per gap, and every row names what closes it.
# --------------------------------------------------------------------------
def _sql_strings(s: Source):
    """SQL assembled by interpolation rather than bound as parameters.

    Looks for a string that contains a SQL verb and is the left operand of %,
    a .format() call, or an f-string. Bound parameters never appear this way,
    so a clean file produces nothing here."""
    sqlish = re.compile(r"\b(select|insert|update|delete)\b", re.I)
    hits = []
    for n in ast.walk(s.tree):
        text = None
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod) and \
                isinstance(n.left, ast.Constant) and isinstance(n.left.value, str):
            text = n.left.value
        elif isinstance(n, ast.JoinedStr):
            text = "".join(v.value for v in n.values
                           if isinstance(v, ast.Constant) and isinstance(v.value, str))
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and \
                n.func.attr == "format" and isinstance(n.func.value, ast.Constant) \
                and isinstance(n.func.value.value, str):
            text = n.func.value.value
        if text and sqlish.search(text):
            hits.append(getattr(n, "lineno", 0))
    return hits


def _request_identity(s: Source):
    """Identity or role taken from the request rather than from a session."""
    pat = re.compile(
        r"request\s*\.\s*(args|form|values|cookies|headers)\s*\.\s*get\s*\(\s*"
        r"[\"'](user|user_id|uid|userid|role|is_admin|admin|name)[\"']", re.I)
    return [m.group(0) for m in pat.finditer(s.code)]


def _shell_from_request(s: Source):
    """A subprocess call with a shell, anywhere in a file that reads requests."""
    hits = []
    for c in s.called("run", "call", "check_output", "Popen", "system", "popen"):
        f = c.func
        mod = f.value.id if isinstance(f, ast.Attribute) and \
            isinstance(f.value, ast.Name) else None
        name = f.attr if isinstance(f, ast.Attribute) else \
            f.id if isinstance(f, ast.Name) else None
        if name in ("system", "popen") and mod == "os":
            hits.append(c.lineno)
        if mod == "subprocess":
            shell = any(k.arg == "shell" and getattr(k.value, "value", False) is True
                        for k in c.keywords)
            if shell or name in ("call", "check_output", "Popen"):
                hits.append(c.lineno)
    return hits


def _model_output_parsed(s: Source):
    """The model's reply read for an instruction rather than displayed.

    Two shapes: a regex or a search against the variable holding the reply, or
    a literal command marker like DISCOUNT: in the source."""
    hits = []
    if re.search(r"(re\s*\.\s*(search|match|findall)|\.\s*startswith|\bin\b)\s*"
                 r"\(?[^\n]{0,60}\b(answer|reply|completion|model_out|response)\b",
                 s.code, re.I):
        hits.append("reply inspected for a marker")
    # A marker the prompt tells the model to emit. ALLCAPS, a colon, then a
    # placeholder. `Content-Security-Policy:` and other header names do not
    # match, because a header is not followed by a placeholder.
    m = re.search(r"\b([A-Z][A-Z_]{2,}):\s*(<[a-z]|\{|%[ds]|\(\\d)", s.code)
    if m:
        hits.append("the prompt contract defines %s as a command marker"
                    % m.group(1))
    return hits


def _prompt_concatenation(s: Source):
    """User text joined onto the system instruction, so there is no boundary."""
    hits = []
    sys_names = re.compile(r"system_?prompt|instructions|system_msg", re.I)
    for n in ast.walk(s.tree):
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            seg = ast.dump(n)
            if sys_names.search(seg) and re.search(
                    r"question|user_text|user_input|message|query", seg, re.I):
                hits.append(n.lineno)
        if isinstance(n, ast.JoinedStr):
            seg = ast.dump(n)
            if sys_names.search(seg) and re.search(r"question|user_text", seg, re.I):
                hits.append(n.lineno)
    return hits


SECRET = re.compile(
    r"[\"'](sk-[A-Za-z0-9_\-]{12,}|sk_live_[A-Za-z0-9]{10,}|"
    r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9\-]{10,})[\"']")


def _secret_in_source(s: Source):
    return [m.group(1)[:14] + "..." for m in SECRET.finditer(s.code)]


def _secret_to_client(s: Source):
    """A secret-looking name interpolated into rendered markup or JS."""
    if not re.search(r"(api_?key|secret|token)", s.code, re.I):
        return []
    hits = []
    # a template that assigns into JS, with a key-ish name passed to the render
    if re.search(r"(const|let|var)\s+\w*(KEY|SECRET|TOKEN)\w*\s*=\s*[\"']\{\{",
                 s.raw, re.I):
        hits.append("rendered into page script")
    if re.search(r"render_template_string\s*\([^)]*\b(key|secret|token)\s*=",
                 s.code, re.I):
        hits.append("passed to the template context")
    if re.search(r"(system_?prompt|instructions)[^\n]{0,80}\+\s*\w*(API_KEY|SECRET|TOKEN)",
                 s.code, re.I):
        hits.append("embedded in the system prompt")
    return hits


def _unescaped_output(s: Source):
    """User or model text reaching markup without escaping."""
    hits = []
    if re.search(r"\{\{\s*\w+\s*\|\s*safe\s*\}\}", s.raw):
        hits.append("|safe in a template")
    if re.search(r"Markup\s*\(\s*(answer|reply|text|body_from|question)", s.code):
        hits.append("Markup() around model or user text")
    # percent-interpolation of a reply straight into an HTML string
    for n in ast.walk(s.tree):
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod) and \
                isinstance(n.left, ast.Constant) and isinstance(n.left.value, str) \
                and re.search(r"<\w+[^>]*>", n.left.value):
            seg = ast.dump(n.right)
            if re.search(r"\b(answer|reply|text|question|term|body)\b", seg) and \
                    "escape" not in seg:
                hits.append("line %d" % n.lineno)
    return hits


def _plaintext_passwords(s: Source):
    """A password compared or selected as a plain column, with no KDF present."""
    kdf = re.search(r"pbkdf2|bcrypt|scrypt|argon2|check_password_hash|"
                    r"generate_password_hash|\bverify\s*\(", s.code, re.I)
    touches = re.search(r"password", s.code, re.I)
    if touches and not kdf:
        return ["no key-derivation function anywhere in the file"]
    if re.search(r"select[^;]{0,80}password[^;]{0,120}(from\s+users)", s.code, re.I) \
            and re.search(r"<th>\s*password", s.raw, re.I):
        return ["the admin view selects and renders the password column"]
    return []


def _no_rate_limit(s: Source):
    if not re.search(r"def\s+login|/login", s.code, re.I):
        return []
    if re.search(r"rate_?limit|limiter|attempts|lockout|too many", s.code, re.I):
        return []
    return ["the login route counts nothing"]


def _no_csrf(s: Source):
    posts = s.count(r"methods\s*=\s*\[[^\]]*POST")
    if not posts:
        return []
    if re.search(r"csrf", s.code, re.I):
        return []
    return ["%d POST route(s), no token" % posts]


def _missing_authz(s: Source):
    """A row fetched by id with no owner predicate and no role gate."""
    hits = []
    for n in ast.walk(s.tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if not (isinstance(f, ast.Attribute) and f.attr == "execute"):
            continue
        seg = ast.dump(n)
        if re.search(r"where\s+id", seg, re.I) and \
                not re.search(r"\band\b", seg, re.I):
            hits.append(n.lineno)
    if hits and not re.search(r"require_admin|require_user|abort\s*\(\s*403",
                              s.code, re.I):
        return ["line %s fetches by id with no owner or role predicate"
                % ", ".join(str(h) for h in hits)]
    return []


def _debug_on(s: Source):
    for c in s.called("run"):
        for k in c.keywords:
            if k.arg == "debug" and getattr(k.value, "value", None) is True:
                return ["app.run(debug=True) at line %d" % c.lineno]
    return []


def _binds_world(s: Source):
    for c in s.called("run"):
        for k in c.keywords:
            if k.arg == "host" and getattr(k.value, "value", None) == "0.0.0.0":
                return ["host=0.0.0.0 at line %d" % c.lineno]
    return []


def _no_model_log(s: Source):
    if not re.search(r"call_model|openai|anthropic|completion", s.code, re.I):
        return []
    if re.search(r"modelog|audit|logger\.|logging\.", s.code, re.I):
        return []
    return ["model calls leave no record"]


def _no_headers(s: Source):
    if re.search(r"Content-Security-Policy", s.raw, re.I):
        return []
    return ["no CSP, no nosniff, no frame-options"]


def _no_waf(s: Source):
    """Requests handled with no application firewall screening them first."""
    if not re.search(r"request\s*\.", s.code):
        return []
    if re.search(r"\bwaf\b|firewall|\bscreen\b|block_owasp", s.code, re.I):
        return []
    return ["requests reach the views with no input firewall in front of them"]


def _no_input_validation(s: Source):
    """Request values consumed with no validation layer."""
    reads = re.search(r"request\s*\.\s*(args|form|values|get_json)", s.code, re.I)
    if not reads:
        return []
    if re.search(r"guardrails|validate|require_int|require_str|clean_str|"
                 r"\bschema\b|ensure_|sanitiz", s.code, re.I):
        return []
    return ["request inputs are used without validation or type checks"]


def _admin_not_isolated(s: Source):
    """The admin console is a route in the same app as the storefront."""
    has_admin = s.has(r"route\s*\(\s*[\"']/admin")
    has_store = s.has(r"route\s*\(\s*[\"']/(cart|catalog)")
    if has_admin and has_store:
        return ["the admin console shares a process and a session with the "
                "storefront"]
    return []


def _llm_overprivileged(s: Source):
    """Model-calling code that can write business state with no capability
    allow-list in front of it."""
    if not re.search(r"call_model|openai|anthropic|completion|chat\s*\.\s*completions",
                     s.code, re.I):
        return []
    writes = False
    for n in ast.walk(s.tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and \
                n.func.attr == "execute":
            if re.search(r"\b(update|insert)\b", ast.dump(n), re.I):
                writes = True
    if not writes:
        return []
    if re.search(r"ASSISTANT_ROLE|assistant_can|capabilit|allow_?list|"
                 r"read_?only|least_priv", s.code, re.I):
        return []
    return ["the assistant can reach a state write with no capability allow-list"]


def _no_audit_log(s: Source):
    """Security-relevant routes with no audit trail."""
    state = s.count(r"methods\s*=\s*\[[^\]]*POST") or \
        re.search(r"def\s+login|/login", s.code, re.I)
    if not state:
        return []
    if re.search(r"\baudit\b|logger\s*\.|logging\s*\.|modelog", s.code, re.I):
        return []
    return ["auth and state changes leave no audit trail"]


CHECKS = [
    dict(id="secret-in-source", sev=HIGH, fn=_secret_in_source,
         means="A provider key is a literal in the repository, so it is in "
               "every clone, every branch and every laptop that pulled it.",
         closes="Read it from the environment and refuse to start without it. "
                "Rotate the leaked one, because it is already spent.",
         fw="OWASP A05 · CIS 3.11 · NIST SC-12"),
    dict(id="secret-to-client", sev=HIGH, fn=_secret_to_client,
         means="The key is rendered into the page or into the prompt, so a "
               "visitor can read it in view-source.",
         closes="Call the provider server side only. The browser never holds "
                "the key and the system prompt never quotes it.",
         fw="OWASP A05 · NIST SC-8"),
    dict(id="identity-in-request", sev=HIGH, fn=_request_identity,
         means="The user id and the role arrive in the request, so the browser "
               "decides who it is. Editing the URL is the privilege escalation.",
         closes="A signed session cookie holds the user id; the role is read "
                "from the database on every request.",
         fw="OWASP A01 · NIST AC-3"),
    dict(id="sql-interpolation", sev=HIGH, fn=_sql_strings,
         means="Queries are assembled by string formatting, so input becomes "
               "grammar. One quote changes what the statement does.",
         closes="Bound parameters. The driver sends the value separately, so "
                "there is nothing for it to escape into.",
         fw="OWASP A03 · CWE-89 · NIST SI-10"),
    dict(id="shell-from-request", sev=HIGH, fn=_shell_from_request,
         means="A request value is placed into a shell string, so a semicolon "
               "runs a second command as the web process.",
         closes="Do the work in the language. If a process is genuinely "
                "needed, pass an argument list and never shell=True.",
         fw="OWASP A03 · CWE-78 · NIST SI-10"),
    dict(id="model-output-as-command", sev=HIGH, fn=_model_output_parsed,
         means="The model's reply is read for an instruction, so whoever can "
               "steer the model can set business state. The price is downstream "
               "of a sentence.",
         closes="Treat the reply as display text. Prices, discounts and actions "
                "come from server-side data and a fixed allow-list.",
         fw="OWASP LLM02 · LLM08 · NIST SI-10"),
    dict(id="unescaped-output", sev=HIGH, fn=_unescaped_output,
         means="User text and model text reach the page as markup, so a review "
               "or an answer can carry script.",
         closes="Escape at the point of rendering, no |safe on untrusted "
                "values, and a CSP that blocks inline script behind it.",
         fw="OWASP A03 · CWE-79 · NIST SI-10"),
    dict(id="plaintext-passwords", sev=HIGH, fn=_plaintext_passwords,
         means="Passwords are stored and compared as written, so the database "
               "is a credential list and the admin page displays it.",
         closes="A salted KDF on write, a constant-time compare on read, and "
                "the password column is never selected by a view.",
         fw="OWASP A02 · A07 · NIST IA-5"),
    dict(id="missing-authorization", sev=HIGH, fn=_missing_authz,
         means="A record is fetched by id with no owner check, so any id "
               "belongs to anyone who asks for it.",
         closes="Put the ownership predicate in the query, not after it, so "
                "one branch cannot forget it.",
         fw="OWASP A01 · CWE-639 · NIST AC-3"),
    dict(id="debug-mode-on", sev=HIGH, fn=_debug_on,
         means="An error returns source, paths and local variables, and the "
               "reloader console can execute code in the process.",
         closes="debug=False, a real WSGI server, and a generic error page.",
         fw="OWASP A05 · CWE-489 · NIST SI-11"),
    dict(id="prompt-concatenation", sev=MED, fn=_prompt_concatenation,
         means="The customer's text is joined onto the system instruction, so "
               "there is no boundary between instruction and data.",
         closes="Separate roles. The instruction and the user's text are "
                "different arguments and never one string.",
         fw="OWASP LLM01 · NIST SI-10"),
    dict(id="no-rate-limit", sev=MED, fn=_no_rate_limit,
         means="The login route accepts unlimited attempts, so the weakest "
               "password in the table is the security of the site.",
         closes="Count attempts per account and per source, lock out on a "
                "threshold, and one message for both failure cases.",
         fw="OWASP A07 · NIST AC-7"),
    dict(id="missing-csrf", sev=MED, fn=_no_csrf,
         means="A state-changing POST carries no token, so another site can "
               "submit it with the victim's cookie.",
         closes="A per-session token in every form, compared in constant time, "
                "and SameSite on the cookie behind it.",
         fw="OWASP A01 · CWE-352"),
    dict(id="binds-all-interfaces", sev=MED, fn=_binds_world,
         means="The development server listens on every interface, so a lab "
               "app is reachable from the network it is on.",
         closes="Bind 127.0.0.1 locally, and put a reverse proxy in front of "
                "it anywhere else.",
         fw="CIS 9.2 · NIST SC-7"),
    dict(id="no-model-audit-log", sev=LOW, fn=_no_model_log,
         means="Model calls leave no record, so a steering attempt that "
                "succeeded and one that failed look identical afterwards.",
         closes="Log who asked, what they asked, what came back, and whether "
                "it matched a detection pattern.",
         fw="OWASP LLM08 · NIST AU-2"),
    dict(id="no-security-headers", sev=LOW, fn=_no_headers,
         means="No CSP and no nosniff, so an escaping mistake has nothing "
               "behind it.",
         closes="CSP without inline script, nosniff, frame-options and a "
                "referrer policy on every response.",
         fw="OWASP A05 · NIST SC-18"),
    dict(id="no-waf", sev=HIGH, fn=_no_waf,
         means="Nothing screens a request before a view runs, so every attack "
               "class reaches application code on the first try, and an attempt "
               "and a success look the same from outside.",
         closes="An input firewall in front of every request that refuses the "
                "OWASP input classes and prompt injection early, and logs the "
                "attempt. Defense in depth, never the only control.",
         fw="OWASP A03 · LLM01 · NIST SI-3 · SC-7"),
    dict(id="no-input-validation", sev=HIGH, fn=_no_input_validation,
         means="Request values are used at the width and type the client sent, "
               "so an oversized, wrong-typed or malformed value reaches a query, "
               "a template or the model unchecked.",
         closes="Validate and bound every value at the edge: type it, limit its "
                "length, reject what does not fit, before it is used.",
         fw="OWASP A03 · ASVS V5 · NIST SI-10"),
    dict(id="admin-not-isolated", sev=HIGH, fn=_admin_not_isolated,
         means="The admin console runs in the same app and shares a session "
               "with the storefront, so a storefront compromise is an admin "
               "compromise and a URL is the only thing between them.",
         closes="Run admin as its own service, on its own port, with its own "
                "login, its own session cookie and its own audit log. The "
                "customer plane has no route to it.",
         fw="OWASP A01 · A04 · NIST AC-6 · SC-7"),
    dict(id="llm-overprivileged", sev=HIGH, fn=_llm_overprivileged,
         means="The assistant runs with the application's own authority: its "
               "path can write business state, so steering the model is a write. "
               "It was given no least-privilege role.",
         closes="Give the assistant a named read-only role and a capability "
                "allow-list. Pricing, orders and accounts are not on it, so a "
                "steered reply has nothing to reach.",
         fw="OWASP LLM06 · LLM08 · NIST AC-6"),
    dict(id="no-audit-log", sev=MED, fn=_no_audit_log,
         means="Sign-ins, admin actions and state changes leave no record, so "
               "there is nothing to detect an attack with and nothing to review "
               "after one.",
         closes="One structured audit line per security event: who, what, when, "
                "from where, and the outcome. A file and stdout, no dependency "
                "that can be down.",
         fw="OWASP A09 · NIST AU-2 · AU-3"),
]

ORDER = {HIGH: 0, MED: 1, LOW: 2}


def scan(path):
    s = Source(path)
    found = []
    for chk in CHECKS:
        ev = chk["fn"](s)
        if ev:
            found.append((chk, ev))
    found.sort(key=lambda f: ORDER[f[0]["sev"]])
    return found


def report(path, found, show_table=False):
    rel = os.path.basename(os.path.dirname(os.path.abspath(path))) + "/" + \
        os.path.basename(path)
    print("appscan " + rel)
    print("-" * 64)
    if not found:
        print("PASS. No findings.")
        print("%d checks ran, 0 gaps." % len(CHECKS))
        return 0
    for chk, ev in found:
        print("[%-6s] %-24s %s" % (chk["sev"], chk["id"], ev[0] if ev else ""))
        for extra in ev[1:4]:
            print("%-9s %-24s %s" % ("", "", extra))
    highs = sum(1 for c, _ in found if c["sev"] == HIGH)
    print("-" * 64)
    print("NAKED. %d gap(s)" % len(found))
    print("%d HIGH. A HIGH finding exits non-zero, so this build fails." % highs)
    if show_table:
        print()
        print_table(found)
    return 1 if highs else 0


def print_table(found):
    print("THE GAPS IN FULL")
    print("=" * 110)
    for chk, _ in found:
        print("%s  [%s]" % (chk["id"], chk["sev"]))
        print("  means : " + chk["means"])
        print("  closes: " + chk["closes"])
        print("  maps  : " + chk["fw"])
        print()


def markdown_table(found):
    rows = ["| Gap | Severity | What it means | What closes it | Maps to |",
            "|---|---|---|---|---|"]
    for chk, _ in found:
        rows.append("| `%s` | %s | %s | %s | %s |" % (
            chk["id"], chk["sev"], chk["means"], chk["closes"], chk["fw"]))
    return "\n".join(rows)


# --------------------------------------------------------------------------
# Selftest. The benign half is the lesson: a gate that fails everything is as
# useless as one that fails nothing.
# --------------------------------------------------------------------------
BAD = {
    "secret-in-source": 'K = "sk-abcdefghijklmnop1234"\n',
    "sql-interpolation": 'q = "SELECT * FROM t WHERE a = \'%s\'" % x\n',
    "shell-from-request": 'import subprocess\nsubprocess.run(c, shell=True)\n',
    "debug-mode-on": 'app.run(debug=True)\n',
    "binds-all-interfaces": 'app.run(host="0.0.0.0")\n',
    "identity-in-request": 'r = request.args.get("role", "user")\n',
    "no-waf": 'x = request.args.get("q")\n',
    "no-input-validation": 'x = request.form.get("q")\n',
    "admin-not-isolated": '@app.route("/admin")\ndef a(): pass\n'
                          '@app.route("/catalog")\ndef c(): pass\n',
    "llm-overprivileged": 'def call_model(q): return q\n'
                          'db.execute("UPDATE widgets SET price = 0")\n',
    "no-audit-log": '@app.route("/x", methods=["POST"])\ndef x(): return 1\n',
}
GOOD = {
    "secret-in-source": 'import os\nK = os.environ["KEY"]\n',
    "sql-interpolation": 'db.execute("SELECT * FROM t WHERE a = ?", (x,))\n',
    "shell-from-request": 'import subprocess\nsubprocess.run(["ls", p])\n',
    "debug-mode-on": 'app.run(debug=False)\n',
    "binds-all-interfaces": 'app.run(host="127.0.0.1")\n',
    "identity-in-request": 'uid = session.get("uid")\n',
    "no-waf": 'import waf\nwaf.block\nx = request.args.get("q")\n',
    "no-input-validation": 'import guardrails\n'
                           'x = guardrails.clean_str(request.form.get("q"), "q")\n',
    "admin-not-isolated": '@app.route("/catalog")\ndef c(): pass\n',
    "llm-overprivileged": 'ASSISTANT_ROLE = "ro"\ndef call_model(q): return q\n'
                          'db.execute("UPDATE widgets SET price = 0")\n',
    "no-audit-log": 'import audit\n@app.route("/x", methods=["POST"])\n'
                    'def x(): audit.log("e")\n',
}
# A benign fixture that mentions every bug in prose. A text-only scanner fails
# this one, which is the reason comments are stripped before anything runs.
PROSE = ('"""This module must never call subprocess with shell=True, never '
         'interpolate SQL, never run with debug=True and never hold an '
         'sk-0000000000000000 style key."""\n# no os.system here either\n'
         'import os\nK = os.environ["KEY"]\n')


def selftest():
    import tempfile
    fails = []

    def ids(text):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(text)
            p = f.name
        try:
            return {c["id"] for c, _ in scan(p)}
        finally:
            os.unlink(p)

    for cid, text in BAD.items():
        got = ids(text)
        if cid not in got:
            fails.append("missed %s in its own bad fixture" % cid)
    for cid, text in GOOD.items():
        got = ids(text)
        if cid in got:
            fails.append("false positive: %s fired on a clean fixture" % cid)
    prose = ids(PROSE)
    for cid in ("shell-from-request", "sql-interpolation", "debug-mode-on",
                "secret-in-source"):
        if cid in prose:
            fails.append("false positive: %s fired on prose only" % cid)

    print("appscan --selftest")
    print("-" * 64)
    print("%d bad fixtures, %d benign fixtures, 1 prose-only fixture"
          % (len(BAD), len(GOOD)))
    if fails:
        for f in fails:
            print("FAIL " + f)
        print("-" * 64)
        print("SELFTEST FAILED. %d problem(s)." % len(fails))
        return 1
    print("-" * 64)
    print("SELFTEST PASSED. Every rule fires on its bug and on nothing else.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="source gate for generated apps")
    ap.add_argument("target", nargs="?", help="a .py file to scan")
    ap.add_argument("--table", action="store_true",
                    help="print the gaps-in-full table under the findings")
    ap.add_argument("--markdown", action="store_true",
                    help="emit the table as markdown for the deck")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.target:
        ap.error("give me a file, or --selftest")
    found = scan(a.target)
    if a.markdown:
        print(markdown_table(found))
        return 0
    return report(a.target, found, show_table=a.table)


if __name__ == "__main__":
    sys.exit(main())
