#!/usr/bin/env python3
"""Prove a fix worked and did not break the app. Never claim "fixed" without this passing.

npm   : lockfile in sync -> resolved versions of the package (none below --fixed) -> npm audit
        -> build (if `build` script / cds build) -> tests
maven : resolved version in `dependency:tree` -> `mvn verify` (tests included unless --skip-tests)

Each step records pass/fail, duration and a log file path; the exit code is non-zero when any
required step fails. Output is JSON.

Usage:
  verify.py npm   --project DIR --package handlebars --fixed 4.7.10 [--install] [--cds-build] [--skip-tests]
  verify.py maven --project DIR --package org.yaml:snakeyaml --fixed 2.2 [--skip-tests] [--maven-args "-P prod"]
"""
import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(__file__))
from common import dump, maven_cmp, semver_cmp  # noqa: E402

LOG_DIR = os.path.join(tempfile.gettempdir(), "secfix-logs")


def run(name, cmd, cwd, timeout, steps, required=True, env=None):
    os.makedirs(LOG_DIR, exist_ok=True)
    exe = shutil.which(cmd[0])
    log = os.path.join(LOG_DIR, f"{int(time.time())}-{re.sub(r'[^a-z0-9]+', '-', name.lower())}.log")
    start = time.time()
    if not exe:
        steps.append({"step": name, "status": "skipped", "reason": f"{cmd[0]} not on PATH", "required": required})
        return None
    try:
        proc = subprocess.run([exe] + cmd[1:], cwd=cwd, capture_output=True, text=True, timeout=timeout,
                              env={**os.environ, **(env or {})})
        out, code = proc.stdout + proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        out, code = (exc.stdout or "") + (exc.stderr or "") + "\n[timeout]", 124
    with open(log, "w", encoding="utf-8") as fh:
        fh.write(out if isinstance(out, str) else out.decode("utf-8", "replace"))
    steps.append({"step": name, "status": "pass" if code == 0 else "fail", "exit_code": code,
                  "seconds": round(time.time() - start, 1), "log": log, "required": required,
                  "tail": "" if code == 0 else out[-800:]})
    return None if code != 0 else out


# --------------------------------------------------------------------------- npm

def verify_npm(a, steps, extra):
    pj_path = os.path.join(a.project, "package.json")
    scripts = json.load(open(pj_path, encoding="utf-8")).get("scripts", {}) if os.path.exists(pj_path) else {}
    if a.install:
        run("npm ci (lockfile in sync, clean install)", ["npm", "ci", "--ignore-scripts"], a.project, a.timeout, steps)
    ls = run(f"npm ls {a.package}", ["npm", "ls", a.package, "--all", "--json", "--long=false"], a.project, 300, steps,
             required=False)
    # `npm ls` exits non-zero on unrelated peer/extraneous problems, so read the tree from the log when it did
    if ls is None and steps[-1].get("log"):
        ls = open(steps[-1]["log"], encoding="utf-8", errors="replace").read()
        steps[-1]["status"] = "pass" if '"dependencies"' in ls else steps[-1]["status"]
    found = sorted(set(re.findall(r'"%s":\s*\{[^{}]*?"version":\s*"([^"]+)"' % re.escape(a.package), ls or "")))
    if ls is not None:
        too_old = [v for v in found if a.fixed and semver_cmp(v, a.fixed) < 0]
        steps.append({"step": f"resolved versions of {a.package}", "required": True,
                      "status": "fail" if too_old else "pass",
                      "found": found, "below_fixed": too_old,
                      "note": "empty list = package no longer in the tree (removed/replaced)" if not found else ""})
    run("npm audit (production deps)", ["npm", "audit", "--omit=dev", "--json"], a.project, 300, steps, required=False)
    if steps[-1]["step"].startswith("npm audit") and steps[-1].get("log"):
        try:
            meta = json.loads(open(steps[-1]["log"], encoding="utf-8", errors="replace").read())
            extra["audit_summary"] = (meta.get("metadata") or {}).get("vulnerabilities")
            steps[-1]["status"] = "info"
        except (json.JSONDecodeError, OSError):
            pass
    if a.cds_build:
        run("cds build --production", ["npx", "--no-install", "cds", "build", "--production"], a.project, a.timeout, steps)
    if "build" in scripts and not a.skip_build:
        run("npm run build", ["npm", "run", "build"], a.project, a.timeout, steps)
    if not a.skip_tests:
        if "test" in scripts:
            run("npm test", ["npm", "test", "--silent"], a.project, a.timeout, steps, env={"CI": "true"})
        else:
            steps.append({"step": "npm test", "status": "skipped", "reason": "no test script in package.json",
                          "required": False})


# --------------------------------------------------------------------------- maven

def verify_maven(a, steps, extra):
    group, _, artifact = a.package.partition(":")
    wrapper = os.path.join(a.project, "mvnw.cmd" if os.name == "nt" else "mvnw")
    mvn = [wrapper] if os.path.exists(wrapper) else ["mvn"]
    extra_args = shlex.split(a.maven_args or "")
    out = run(f"mvn dependency:tree -Dincludes={a.package}",
              mvn + ["-B", "-ntp", "dependency:tree", f"-Dincludes={a.package}"] + extra_args, a.project, 900, steps)
    if out is not None:
        found = sorted(set(re.findall(rf"{re.escape(group)}:{re.escape(artifact)}:[\w-]+:([^:\s]+)", out)))
        too_old = [v for v in found if a.fixed and maven_cmp(v, a.fixed) < 0]
        steps.append({"step": f"resolved versions of {a.package}", "required": True,
                      "status": "fail" if too_old else "pass", "found": found, "below_fixed": too_old})
    goals = ["-B", "-ntp", "verify"] + (["-DskipTests"] if a.skip_tests else [])
    run("mvn verify" + (" (tests skipped)" if a.skip_tests else ""), mvn + goals + extra_args, a.project, a.timeout, steps)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ecosystem", choices=["npm", "maven"])
    ap.add_argument("--project", default=".")
    ap.add_argument("--package", required=True)
    ap.add_argument("--fixed", help="minimum acceptable version of the package")
    ap.add_argument("--install", action="store_true", help="(npm) run `npm ci --ignore-scripts` first")
    ap.add_argument("--cds-build", action="store_true", help="(npm) also run `cds build --production`")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--skip-tests", action="store_true")
    ap.add_argument("--maven-args", help="extra args, e.g. \"-P prod -pl srv -am\"")
    ap.add_argument("--timeout", type=int, default=1200)
    a = ap.parse_args()
    a.project = os.path.abspath(a.project)
    steps, extra = [], {}
    (verify_npm if a.ecosystem == "npm" else verify_maven)(a, steps, extra)
    failed = [s["step"] for s in steps if s.get("required") and s["status"] == "fail"]
    dump({"verdict": "FAIL" if failed else "PASS", "failed_steps": failed, "steps": steps, **extra,
          "reminder": "PASS only covers the steps above; skipped steps (no tests, no build) mean the app was NOT fully exercised: say so."})
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
