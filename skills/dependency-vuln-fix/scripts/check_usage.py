#!/usr/bin/env python3
"""Heuristic reachability check: does YOUR code import/use the vulnerable package?

Scans first-party sources only (skips node_modules, target, gen, dist, build, .git ...).
Reports (1) import/require hits, (2) hits of known risky call patterns from
references/known-sinks.json (plus --pattern extras). Heuristic, not proof: a
"no hits" result on a transitive package means "not obviously used by our code",
the vulnerable code may still run inside the parent library.

Usage:
  check_usage.py --project DIR --package handlebars [--ecosystem npm] [--pattern 'compile\\('] [--max-hits 40]
  check_usage.py --project DIR --package org.yaml:snakeyaml --ecosystem maven
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import dump  # noqa: E402

SKIP_DIRS = {"node_modules", "target", "gen", ".git", "dist", "build", "mta_archives", ".mvn", ".idea",
             ".vscode", "coverage", "out", ".venv", "__pycache__", "resources_gen"}
NPM_EXT = {".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx", ".cds", ".json", ".hbs", ".yaml", ".yml"}
MVN_EXT = {".java", ".kt", ".xml", ".properties", ".yaml", ".yml", ".cds"}
SKIP_FILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}
SINKS_FILE = os.path.join(os.path.dirname(__file__), "..", "references", "known-sinks.json")


def candidates(project, exts):
    for dirpath, dirnames, files in os.walk(project):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in files:
            if name in SKIP_FILES or name.endswith(".min.js") or os.path.splitext(name)[1] not in exts:
                continue
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) <= 1_000_000:
                    yield path
            except OSError:
                continue


def scan(project, exts, regexes, max_hits):
    hits = []
    for path in candidates(project, exts):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for no, line in enumerate(fh, 1):
                    for label, rx in regexes:
                        if rx.search(line):
                            hits.append({"file": os.path.relpath(path, project).replace(os.sep, "/"),
                                         "line": no, "kind": label, "text": line.strip()[:160]})
                            break
        except OSError:
            continue
        if len(hits) >= max_hits:
            break
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", default=".")
    ap.add_argument("--package", required=True)
    ap.add_argument("--ecosystem", choices=["npm", "maven"], default="npm")
    ap.add_argument("--pattern", action="append", default=[], help="extra regex for risky usage (repeatable)")
    ap.add_argument("--max-hits", type=int, default=40)
    a = ap.parse_args()
    project = os.path.abspath(a.project)

    with open(SINKS_FILE, encoding="utf-8") as fh:
        sinks = json.load(fh).get(a.ecosystem, {})
    known = sinks.get(a.package, {})
    patterns = known.get("patterns", []) + a.pattern

    if a.ecosystem == "npm":
        name = re.escape(a.package)
        imports = [("import", re.compile(rf"""(require\(\s*['"]{name}(?:/[^'"]*)?['"]\s*\)|from\s+['"]{name}(?:/[^'"]*)?['"]|import\s+['"]{name}['"])""")),
                   ("package.json/script", re.compile(rf"""["'\s/]{name}["'\s@]"""))]
        exts = NPM_EXT
    else:
        group, _, artifact = a.package.partition(":")
        prefix = re.escape(group)
        imports = [("import", re.compile(rf"\bimport\s+(static\s+)?{prefix}[\w.]*")),
                   ("pom/xml", re.compile(rf"<artifactId>\s*{re.escape(artifact)}\s*</artifactId>"))]
        exts = MVN_EXT

    import_hits = scan(project, exts, imports, a.max_hits)
    risky = scan(project, exts - {".json", ".yaml", ".yml"} if a.ecosystem == "npm" else exts,
                 [("risky-pattern", re.compile(p)) for p in patterns], a.max_hits) if patterns else []
    # a package.json hit on its own declares the dependency, it does not use it
    used_in_code = [h for h in import_hits if h["kind"] == "import"]
    if used_in_code and risky:
        verdict = "LIKELY_REACHABLE"
    elif used_in_code:
        verdict = "IMPORTED_NO_KNOWN_RISKY_CALL"
    elif risky:
        verdict = "RISKY_PATTERN_WITHOUT_IMPORT"
    else:
        verdict = "NOT_OBVIOUSLY_USED"
    dump({
        "package": a.package, "ecosystem": a.ecosystem, "verdict": verdict,
        "advisory_note": known.get("note"), "patterns_used": patterns,
        "import_hits": import_hits, "risky_hits": risky,
        "caveat": "Heuristic only. For transitive packages, vulnerable code can run inside the parent "
                  "library even with zero hits here. Confirm preconditions in the advisory text.",
    })


if __name__ == "__main__":
    main()
