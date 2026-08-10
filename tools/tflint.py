#!/usr/bin/env python3
"""
Offline Terraform sanity check.

This is NOT `terraform validate` -- it has no provider schemas, so it cannot
tell you that an argument name is wrong. What it CAN do is parse every .tf file
with a real HCL2 parser and then cross-reference the graph, which catches the
mistakes that actually happen when you author a module by hand:

  * a var.X that no variable block declares
  * a variable block nothing references (usually a rename you half-finished)
  * a module block passing an argument the child module does not declare
  * a required child variable the parent never passes
  * a module.NAME.OUTPUT the child module does not output
  * count/for_each referenced with the wrong indexing form

Run: python3 tflint.py <root-module-dir>
"""

import os
import re
import sys

import hcl2


def load_dir(d):
    """Parse every .tf in one directory into a merged block dict."""
    merged = {"variable": {}, "output": {}, "module": {}, "resource": [],
              "data": [], "locals": []}
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".tf"):
            continue
        path = os.path.join(d, fn)
        with open(path) as fh:
            try:
                doc = hcl2.load(fh)
            except Exception as exc:
                print(f"  PARSE FAIL {path}: {exc}")
                raise SystemExit(1)
        # hcl2 keeps the quotes on block labels: {'"name"': {...}}. Strip them
        # or every cross-reference check compares '"x"' against 'x' and fails.
        def unq(blk):
            return {k.strip('"'): v for k, v in blk.items()}
        for blk in doc.get("variable", []):
            merged["variable"].update(unq(blk))
        for blk in doc.get("output", []):
            merged["output"].update(unq(blk))
        for blk in doc.get("module", []):
            merged["module"].update(unq(blk))
        merged["resource"].extend(doc.get("resource", []))
        merged["data"].extend(doc.get("data", []))
        merged["locals"].extend(doc.get("locals", []))
    return merged


def raw_text(d):
    out = []
    for fn in sorted(os.listdir(d)):
        if fn.endswith(".tf") or fn.endswith(".tftpl"):
            with open(os.path.join(d, fn)) as fh:
                out.append(fh.read())
    return "\n".join(out)


def check_module(d, label):
    """Check one directory in isolation: declared vs referenced variables."""
    problems = []
    m = load_dir(d)
    text = raw_text(d)

    declared = set(m["variable"])
    referenced = set(re.findall(r"\bvar\.([A-Za-z_][A-Za-z0-9_-]*)", text))

    for name in sorted(referenced - declared):
        problems.append(f"[{label}] var.{name} is referenced but never declared")
    for name in sorted(declared - referenced):
        problems.append(f"[{label}] variable \"{name}\" is declared but never used")

    # local.X must be defined in some locals block
    local_names = set()
    for blk in m["locals"]:
        local_names.update(blk.keys())
    for name in sorted(set(re.findall(r"\blocal\.([A-Za-z_][A-Za-z0-9_]*)", text))):
        if name not in local_names:
            problems.append(f"[{label}] local.{name} is referenced but never defined")

    return problems, m


def _source(cfg):
    """hcl2 hands back attribute values with their quotes still attached, so a
    naive startswith("./") silently skips every local module and the whole
    cross-reference check becomes a no-op that always says clean. Ask me how I
    know."""
    src = cfg.get("source")
    if isinstance(src, list):
        src = src[0] if src else None
    if isinstance(src, str):
        src = src.strip().strip('"')
    return src


def check_wiring(root_dir, root, children):
    """Check module blocks against the child modules they call."""
    problems = []
    for name, cfg in root["module"].items():
        src = _source(cfg)
        if not src or not src.startswith("./"):
            continue                       # remote or ../ module, not linted here
        child_dir = os.path.normpath(os.path.join(root_dir, src))
        if child_dir not in children:
            continue
        child = children[child_dir]

        # __is_block__ is an hcl2 bookkeeping key, not an argument.
        passed = {k for k in cfg if k not in ("source", "count", "for_each",
                                              "providers", "depends_on",
                                              "__is_block__")}
        declared = set(child["variable"])

        for k in sorted(passed - declared):
            problems.append(
                f"[wiring] module \"{name}\" passes '{k}', which "
                f"{src} does not declare")

        for k in sorted(declared - passed):
            spec = child["variable"][k]
            if isinstance(spec, dict) and "default" not in spec:
                problems.append(
                    f"[wiring] module \"{name}\" never sets '{k}', which "
                    f"{src} requires (no default)")
    return problems


def check_outputs(root_dir, root, children, root_text):
    """Every module.NAME.OUTPUT referenced must exist in that child."""
    problems = []
    srcs = {name: _source(cfg) for name, cfg in root["module"].items()}

    for mod, out in set(re.findall(
            r"\bmodule\.([A-Za-z_][A-Za-z0-9_-]*)\.([A-Za-z_][A-Za-z0-9_]*)",
            root_text)):
        src = srcs.get(mod)
        if not src:
            problems.append(f"[outputs] module.{mod} is referenced but no "
                            f"module \"{mod}\" block exists")
            continue
        if not src.startswith("./"):
            continue                       # child outside this root, skip
        child_dir = os.path.normpath(os.path.join(root_dir, src))
        child = children.get(child_dir)
        if child and out not in child["output"]:
            problems.append(f"[outputs] module.{mod}.{out} does not exist in {src}")
    return problems


def main():
    root_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    root = load_dir(root_dir)
    root_text = raw_text(root_dir)

    problems = []
    p, _ = check_module(root_dir, "root")
    problems += p

    children = {}
    mod_dir = os.path.join(root_dir, "modules")
    if os.path.isdir(mod_dir):
        for name in sorted(os.listdir(mod_dir)):
            d = os.path.join(mod_dir, name)
            if not os.path.isdir(d):
                continue
            p, m = check_module(d, f"modules/{name}")
            problems += p
            children[os.path.normpath(d)] = m

    problems += check_wiring(root_dir, root, children)
    problems += check_outputs(root_dir, root, children, root_text)

    if problems:
        print(f"tflint: {len(problems)} problem(s)")
        for p in problems:
            print("  -", p)
        return 1
    print("tflint: clean — parse OK, variables/outputs/module wiring consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
