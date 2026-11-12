#!/usr/bin/env python3
"""PostToolUse hook: after a dependency manifest/lockfile is edited, remind the model of the
checks that must run before it can say "fixed". Adds context only; never blocks. Fails open."""
import json
import os
import sys

MANIFESTS = {
    "package.json": "regenerate the lockfile (`npm install --package-lock-only --ignore-scripts`) so package.json and package-lock.json stay in sync, else `npm ci` fails in the pipeline",
    "package-lock.json": "confirm the resolved version with `npm ls <pkg> --all`; do not hand-edit lockfiles",
    "npm-shrinkwrap.json": "confirm the resolved version with `npm ls <pkg> --all`",
    "pom.xml": "re-run `mvn dependency:tree -Dincludes=<g:a>` to confirm the resolved version, then `mvn verify`",
    "build.gradle": "re-run `gradle dependencyInsight --dependency <name>` to confirm the resolved version",
    "build.gradle.kts": "re-run `gradle dependencyInsight --dependency <name>` to confirm the resolved version",
    "mta.yaml": "mta build runs `npm ci` per module: make sure each module's lockfile is in sync",
}


def main():
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)
    path = ((event.get("tool_input") or {}).get("file_path") or "")
    hint = MANIFESTS.get(os.path.basename(path))
    if not hint:
        sys.exit(0)
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "additionalContext": (f"dependency-vuln-fix: `{os.path.basename(path)}` was edited. Next: {hint}. "
                              "Then run scripts/verify.py. Do not report the vulnerability as fixed until verify.py returns PASS.")}}))
    sys.exit(0)


if __name__ == "__main__":
    main()
