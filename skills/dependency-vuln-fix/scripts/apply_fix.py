#!/usr/bin/env python3
"""Apply a dependency fix to manifests. DRY-RUN by default: prints a diff, writes nothing.

npm
  apply_fix.py npm --project DIR --package handlebars --version 4.7.10 [--strategy auto|override|direct|lock-refresh]
                   [--parent hbs] [--exact] [--apply] [--refresh-lock]
  override     : adds overrides (yarn: resolutions, pnpm: pnpm.overrides) so the transitive copy resolves to >= fixed
  direct       : bumps the range in dependencies/devDependencies/optionalDependencies
  lock-refresh : no manifest change; runs `npm update <pkg> --package-lock-only` (only valid if parent ranges allow it)
  --parent     : scope the override to one parent package (smaller blast radius)

maven
  apply_fix.py maven --pom POM --group G --artifact A --version V [--mode auto|bump|manage|property]
                     [--property NAME] [--allow-shared-property] [--apply]
  bump     : change the declared <version> (or the ${property} it points to)
  manage   : add/update an entry in <dependencyManagement> (wins over parent and imported BOMs)
  property : set a version property that a parent/BOM reads (e.g. snakeyaml.version, jackson-bom.version)

Gradle is not edited automatically: see references/maven-java-fixes.md for constraints{} snippets.
Nothing here commits, pushes, or contacts a remote.
"""
import argparse
import difflib
import json
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import dump  # noqa: E402


def diff(path, old, new):
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                        f"a/{path}", f"b/{path}"))


def read(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


# =========================================================================== npm

def detect_indent(text):
    m = re.search(r'^(\s+)"', text, re.M)
    return m.group(1) if m else "  "


def npm_apply(a):
    pj_path = os.path.join(a.project, "package.json")
    if not os.path.exists(pj_path):
        return {"error": f"{pj_path} not found"}
    old = read(pj_path)
    pkg = json.loads(old)
    indent = detect_indent(old)
    eol = "\r\n" if "\r\n" in old else "\n"
    pm = ("pnpm" if os.path.exists(os.path.join(a.project, "pnpm-lock.yaml")) else
          "yarn" if os.path.exists(os.path.join(a.project, "yarn.lock")) else "npm")
    value = a.version if a.exact else "^" + a.version
    direct_sections = [s for s in ("dependencies", "devDependencies", "optionalDependencies")
                       if a.package in (pkg.get(s) or {})]

    strategy = a.strategy
    if strategy == "auto":
        strategy = "direct" if direct_sections else "override"
    notes = []

    if strategy == "lock-refresh":
        cmd = [shutil.which("npm") or "npm", "update", a.package, "--package-lock-only", "--ignore-scripts"]
        res = {"strategy": strategy, "pm": pm, "manifest_changed": False, "command": " ".join(cmd[1:])}
        if a.apply:
            proc = subprocess.run(cmd, cwd=a.project, capture_output=True, text=True, timeout=600)
            res.update(applied=True, returncode=proc.returncode, output=(proc.stdout + proc.stderr)[-1500:])
        return res

    if strategy == "direct":
        if not direct_sections:
            return {"error": f"{a.package} is not declared in package.json dependencies; use --strategy override"}
        for s in direct_sections:
            pkg[s][a.package] = value
        # an existing override that conflicts with the direct spec makes npm fail with EOVERRIDE
        ov = (pkg.get("overrides") or {})
        if a.package in ov and isinstance(ov[a.package], str):
            notes.append(f"existing override '{a.package}': '{ov[a.package]}' remains; make it '${a.package}' "
                         "or remove it so it cannot conflict with the direct range")
    else:  # override
        if direct_sections and not a.parent:
            notes.append("package is ALSO a direct dependency: npm rejects a conflicting override (EOVERRIDE); "
                         "prefer --strategy direct")
        if pm == "pnpm":
            ov = pkg.setdefault("pnpm", {}).setdefault("overrides", {})
            ov[f"{a.parent}>{a.package}" if a.parent else a.package] = value
        elif pm == "yarn":
            ov = pkg.setdefault("resolutions", {})
            ov[f"{a.parent}/{a.package}" if a.parent else a.package] = value
        else:
            ov = pkg.setdefault("overrides", {})
            if a.parent:
                scoped = ov.get(a.parent)
                if not isinstance(scoped, dict):
                    scoped = {".": scoped} if isinstance(scoped, str) else {}
                scoped[a.package] = value
                ov[a.parent] = scoped
            else:
                cur = ov.get(a.package)
                if isinstance(cur, dict):
                    cur["."] = value
                else:
                    ov[a.package] = value
        if pm == "npm" and any(os.path.exists(os.path.join(a.project, d)) for d in ("srv", "app", "db")) \
                and pkg.get("workspaces") is None:
            notes.append("CAP project: overrides only take effect in the package.json that owns the lockfile being installed "
                         "(root, unless srv/ has its own lockfile used by the MTA build).")

    new = json.dumps(pkg, indent=len(indent) if indent != "\t" else "\t", ensure_ascii=False) + eol
    if old.rstrip("\r\n") == new.rstrip("\r\n"):
        return {"strategy": strategy, "changed": False, "notes": notes + ["already set; nothing to change"]}
    res = {"strategy": strategy, "pm": pm, "file": "package.json", "changed": True,
           "diff": diff("package.json", old, new), "notes": notes, "applied": False}
    if a.apply:
        write(pj_path, new)
        res["applied"] = True
        if a.refresh_lock:
            cmd = {"npm": ["npm", "install", "--package-lock-only", "--ignore-scripts"],
                   "yarn": ["yarn", "install", "--mode", "update-lockfile"],
                   "pnpm": ["pnpm", "install", "--lockfile-only", "--ignore-scripts"]}[pm]
            exe = shutil.which(cmd[0])
            if not exe:
                res["lock_refresh"] = f"{cmd[0]} not found on PATH; run `{' '.join(cmd)}` yourself"
            else:
                proc = subprocess.run([exe] + cmd[1:], cwd=a.project, capture_output=True, text=True, timeout=900)
                res["lock_refresh"] = {"command": " ".join(cmd), "returncode": proc.returncode,
                                       "output": (proc.stdout + proc.stderr)[-1500:]}
    return res


# =========================================================================== maven

def pom_indent(text):
    m = re.search(r"^([ \t]*)<modelVersion>", text, re.M)
    base = m.group(1) if m else "    "
    unit = "\t" if "\t" in base else (" " * (len(base) or 4))
    return base, unit


def _section_at(text, pos):
    """Return 'dependencyManagement', 'plugin', or 'dependencies' for a <dependency> at `pos`."""
    before = text[:pos]
    if before.rfind("<dependencyManagement>") > before.rfind("</dependencyManagement>"):
        return "dependencyManagement"
    if before.rfind("<plugin>") > before.rfind("</plugin>"):
        return "plugin"
    return "dependencies"


def maven_apply(a):
    old = read(a.pom)
    new = old
    eol = "\r\n" if "\r\n" in old else "\n"
    base, unit = pom_indent(old)
    notes, mode = [], a.mode

    def set_property(text, name, value):
        rx = re.compile(rf"(<{re.escape(name)}>)(.*?)(</{re.escape(name)}>)", re.S)
        if rx.search(text):
            return rx.sub(lambda m: m.group(1) + value + m.group(3), text, 1), True
        if "<properties>" in text:
            return re.sub(r"(<properties>[ \t]*\r?\n)", lambda m: m.group(1) + f"{base}{unit}<{name}>{value}</{name}>{eol}", text, 1), True
        anchor = re.search(r"</parent>[ \t]*\r?\n|<modelVersion>.*?</modelVersion>[ \t]*\r?\n", text)
        block = f"{base}<properties>{eol}{base}{unit}<{name}>{value}</{name}>{eol}{base}</properties>{eol}"
        return (text[:anchor.end()] + block + text[anchor.end():] if anchor else text), bool(anchor)

    if mode == "property":
        if not a.property:
            return {"error": "--mode property needs --property NAME"}
        new, ok = set_property(old, a.property, a.version)
        if not ok:
            return {"error": "could not place the property; edit <properties> manually"}
    else:
        blocks = [m for m in re.finditer(r"<dependency>(.*?)</dependency>", old, re.S)
                  if re.search(rf"<groupId>\s*{re.escape(a.group)}\s*</groupId>", m.group(1))
                  and re.search(rf"<artifactId>\s*{re.escape(a.artifact)}\s*</artifactId>", m.group(1))
                  and _section_at(old, m.start()) != "plugin"]
        if mode == "auto":
            mode = "bump" if blocks else "manage"
        if mode == "bump":
            # prefer the dependencyManagement entry, else the direct declaration
            blocks.sort(key=lambda m: _section_at(old, m.start()) != "dependencyManagement")
            target = next((m for m in blocks if re.search(r"<version>", m.group(1))), None)
            if not target:
                notes.append("declared without a <version> (inherited from parent/BOM): falling back to dependencyManagement")
                mode = "manage"
            else:
                ver = re.search(r"<version>\s*(.*?)\s*</version>", target.group(1)).group(1)
                prop = re.fullmatch(r"\$\{(.+)\}", ver)
                if prop:
                    uses = old.count("${" + prop.group(1) + "}")
                    if uses > 1 and not a.allow_shared_property:
                        return {"error": f"property {prop.group(1)} is used {uses} times: changing it upgrades every "
                                         "artifact that shares it. Re-run with --allow-shared-property if intended, "
                                         "or --mode manage to pin only this artifact."}
                    new, _ = set_property(old, prop.group(1), a.version)
                else:
                    start, end = target.start(1), target.end(1)
                    seg = re.sub(r"(<version>\s*)(.*?)(\s*</version>)", lambda m: m.group(1) + a.version + m.group(3),
                                 old[start:end], 1)
                    new = old[:start] + seg + old[end:]
        if mode == "manage":
            entry_ind = base + unit * 2
            entry = (f"{entry_ind}<dependency>{eol}"
                     f"{entry_ind}{unit}<groupId>{a.group}</groupId>{eol}"
                     f"{entry_ind}{unit}<artifactId>{a.artifact}</artifactId>{eol}"
                     f"{entry_ind}{unit}<version>{a.version}</version>{eol}"
                     f"{entry_ind}</dependency>{eol}")
            dm = re.search(r"<dependencyManagement>.*?</dependencyManagement>", old, re.S)
            managed = None
            if dm:
                for m in re.finditer(r"<dependency>(.*?)</dependency>", dm.group(0), re.S):
                    if (f"<artifactId>{a.artifact}</artifactId>" in m.group(1)
                            and f"<groupId>{a.group}</groupId>" in m.group(1)):
                        managed = m
                if managed:
                    s = dm.start() + managed.start(1)
                    seg = re.sub(r"(<version>\s*)(.*?)(\s*</version>)", lambda m: m.group(1) + a.version + m.group(3),
                                 managed.group(1), 1)
                    new = old[:s] + seg + old[s + len(managed.group(1)):]
                else:
                    close = old.index("</dependencies>", dm.start())
                    line_start = old.rfind("\n", 0, close) + 1
                    new = old[:line_start] + entry + old[line_start:]
            else:
                block = (f"{base}<dependencyManagement>{eol}{base}{unit}<dependencies>{eol}{entry}"
                         f"{base}{unit}</dependencies>{eol}{base}</dependencyManagement>{eol}")
                top = re.search(rf"(?m)^{re.escape(base)}<dependencies>", old)
                at = top.start() if top else old.rindex("</project>")
                new = old[:at] + block + old[at:]
            notes.append("managed entries declared in this pom take precedence over the parent and imported BOMs")

    if new == old:
        return {"changed": False, "notes": notes + ["no change produced (already at that version?)"]}
    res = {"mode": mode, "file": a.pom, "changed": True, "diff": diff(os.path.basename(a.pom), old, new),
           "notes": notes, "applied": False}
    if a.apply:
        write(a.pom, new)
        res["applied"] = True
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="eco", required=True)
    n = sub.add_parser("npm")
    n.add_argument("--project", default=".")
    n.add_argument("--package", required=True)
    n.add_argument("--version", required=True)
    n.add_argument("--strategy", choices=["auto", "override", "direct", "lock-refresh"], default="auto")
    n.add_argument("--parent")
    n.add_argument("--exact", action="store_true", help="pin exact version instead of ^range")
    n.add_argument("--apply", action="store_true")
    n.add_argument("--refresh-lock", action="store_true", help="after --apply, regenerate the lockfile (no node_modules, no scripts)")
    m = sub.add_parser("maven")
    m.add_argument("--pom", required=True)
    m.add_argument("--group", required=True)
    m.add_argument("--artifact", required=True)
    m.add_argument("--version", required=True)
    m.add_argument("--mode", choices=["auto", "bump", "manage", "property"], default="auto")
    m.add_argument("--property")
    m.add_argument("--allow-shared-property", action="store_true")
    m.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    if a.eco == "npm":
        a.project = os.path.abspath(a.project)
    dump(npm_apply(a) if a.eco == "npm" else maven_apply(a))


if __name__ == "__main__":
    main()
