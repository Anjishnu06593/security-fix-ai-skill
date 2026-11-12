#!/usr/bin/env python3
"""Find how a vulnerable package got into the project: direct vs transitive, and via whom.

npm   : parses package-lock.json / npm-shrinkwrap.json (lockfileVersion 2 or 3).
maven : parses `mvn dependency:tree` output (runs it when --tree is not given and mvn exists)
        and inspects pom.xml files for where the artifact/version is declared.

Usage:
  trace_dependency.py npm   --project DIR --package handlebars [--fixed 4.7.10]
  trace_dependency.py maven --project DIR --package org.yaml:snakeyaml [--tree tree.txt] [--fixed 2.2]

`--fixed` lets the script say whether each parent's declared range already allows the
fixed version (=> a lockfile refresh is enough, no override needed).
"""
import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import deque

sys.path.insert(0, os.path.dirname(__file__))
from common import dump, maven_cmp, satisfies, semver_cmp  # noqa: E402

SKIP_DIRS = {"node_modules", "target", "gen", ".git", "dist", "build", "mta_archives", ".mvn"}


# =========================================================================== npm

def _resolve(packages, frm, name):
    """Node resolution inside a v2/v3 lockfile `packages` map."""
    base = frm
    while True:
        cand = (base + "/" if base else "") + "node_modules/" + name
        if cand in packages:
            return cand
        if not base:
            return None
        idx = base.rfind("node_modules/")
        base = "" if idx == -1 else base[:idx].rstrip("/")


def trace_npm(project, package, fixed):
    lock_path = next((os.path.join(project, n) for n in ("package-lock.json", "npm-shrinkwrap.json")
                      if os.path.exists(os.path.join(project, n))), None)
    if not lock_path:
        other = [n for n in ("yarn.lock", "pnpm-lock.yaml") if os.path.exists(os.path.join(project, n))]
        return {"error": "no package-lock.json found", "hint":
                (f"found {other[0]}: run `{'yarn why' if other[0] == 'yarn.lock' else 'pnpm why'} {package}`"
                 if other else "run `npm install --package-lock-only` first, or `npm ls " + package + " --all`")}
    with open(lock_path, encoding="utf-8") as fh:
        lock = json.load(fh)
    version = lock.get("lockfileVersion")
    packages = lock.get("packages")
    if not packages:
        return {"error": f"lockfileVersion {version} has no `packages` map (npm 6 lockfile)",
                "hint": f"run `npm install --package-lock-only` with npm>=7 to upgrade it, or use `npm ls {package} --all`"}

    root = packages.get("", {})
    edges, reverse = {}, {}
    for key, meta in packages.items():
        out = []
        kinds = ["dependencies", "optionalDependencies", "peerDependencies"] + (["devDependencies"] if key == "" else [])
        for kind in kinds:
            for dep, rng in (meta.get(kind) or {}).items():
                tgt = _resolve(packages, key, dep)
                if tgt:
                    out.append((tgt, dep, rng, kind))
        if meta.get("link") and meta.get("resolved") in packages:
            out.append((meta["resolved"], meta.get("name", key), "link", "link"))
        if key and "node_modules/" not in key and not meta.get("link"):  # workspace member
            edges.setdefault("", []).append((key, key, "workspace", "workspace"))
        edges.setdefault(key, []).extend(out)
        for tgt, dep, rng, kind in out:
            reverse.setdefault(tgt, []).append((key, dep, rng, kind))

    # shortest chain from root to each node (BFS)
    parent = {"": None}
    q = deque([""])
    while q:
        cur = q.popleft()
        for tgt, *_ in edges.get(cur, []):
            if tgt not in parent:
                parent[tgt] = cur
                q.append(tgt)

    def label(k):
        if k == "":
            return root.get("name", "<root>")
        m = packages[k]
        return f"{m.get('name') or k.split('node_modules/')[-1]}@{m.get('version', '?')}"

    instances = []
    for key, meta in packages.items():
        if not key.endswith("node_modules/" + package) and meta.get("name") != package:
            continue
        if meta.get("link"):
            continue
        chain, cur = [], key
        while cur is not None:
            chain.append(label(cur))
            cur = parent.get(cur)
        chain.reverse()
        dependents = []
        for frm, dep, rng, kind in reverse.get(key, []):
            dependents.append({
                "dependent": label(frm), "declared_range": rng, "kind": kind,
                "range_allows_fixed": (satisfies(fixed, rng) if fixed else None),
            })
        instances.append({
            "path": key, "version": meta.get("version"), "dev_only": bool(meta.get("dev")),
            "optional": bool(meta.get("optional")), "reachable_from_root": key in parent,
            "direct": _is_direct(package, root, dependents),
            "shortest_chain": chain, "dependents": dependents,
            # a transitive copy whose parent range excludes the fixed version cannot be fixed by a lock refresh
            "needs_override": bool(fixed) and not _is_direct(package, root, dependents)
                              and any(d["range_allows_fixed"] is False for d in dependents),
            "lock_refresh_may_suffice": bool(fixed) and bool(dependents)
                              and all(d["range_allows_fixed"] for d in dependents),
        })

    pkg_json = {}
    pj = os.path.join(project, "package.json")
    if os.path.exists(pj):
        with open(pj, encoding="utf-8") as fh:
            pkg_json = json.load(fh)
    pm = "pnpm" if os.path.exists(os.path.join(project, "pnpm-lock.yaml")) else (
        "yarn" if os.path.exists(os.path.join(project, "yarn.lock")) else "npm")
    return {
        "ecosystem": "npm", "lockfile": os.path.relpath(lock_path, project), "lockfileVersion": version,
        "package_manager": pm,
        "workspaces": pkg_json.get("workspaces"),
        "existing_overrides": pkg_json.get("overrides") or pkg_json.get("resolutions") or (pkg_json.get("pnpm") or {}).get("overrides"),
        "declared_in_root": {k: pkg_json.get(k, {}).get(package) for k in ("dependencies", "devDependencies", "optionalDependencies") if package in pkg_json.get(k, {})},
        "package": package, "instances": instances, "summary": _summarize(instances, fixed),
    }


def _is_direct(package, root, dependents):
    declared = {**(root.get("dependencies") or {}), **(root.get("devDependencies") or {}),
                **(root.get("optionalDependencies") or {})}
    return package in declared


def _summarize(instances, fixed):
    if not instances:
        return "package not found in lockfile (already removed, renamed, or a different lockfile is scanned)"
    parts = []
    for i in instances:
        scope = "direct" if i["direct"] else "transitive"
        dev = ", dev-only" if i["dev_only"] else ""
        via = " via " + " > ".join(i["shortest_chain"][1:-1]) if not i["direct"] and len(i["shortest_chain"]) > 2 else ""
        parts.append(f"{i['path']} {i['version']} ({scope}{dev}){via}")
    return "; ".join(parts)


# =========================================================================== maven

TREE_LINE = re.compile(r"^(?:\[INFO\]\s)?((?:[|\s]{2}\s)*)?(?:([+\\])-\s)?([^\s].*)$")


def parse_maven_tree(text):
    """Return list of nodes: {depth, gav:{g,a,type,version,scope}, path:[...ancestors]}."""
    nodes, stack = [], []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.startswith("[INFO]"):
            continue
        body = line[len("[INFO] "):]
        m = re.match(r"^((?:[| ] {2})*)([+\\]- )?(\S+:\S+)", body)
        if not m or ":" not in m.group(3):
            continue
        indent, marker, coords = m.group(1), m.group(2), m.group(3)
        if marker is None and indent:
            continue
        depth = len(indent) // 3 + (1 if marker else 0)
        parts = coords.split(":")
        if len(parts) < 4:
            continue
        scope = parts[-1] if parts[-1] in ("compile", "runtime", "test", "provided", "system", "import") else None
        ver_idx = -2 if scope else -1
        node = {"depth": depth, "group": parts[0], "artifact": parts[1], "type": parts[2],
                "version": parts[ver_idx], "scope": scope}
        del stack[depth:]
        stack.append(node)
        node["path"] = [f"{n['group']}:{n['artifact']}:{n['version']}" for n in stack]
        nodes.append(node)
    return nodes


def _strip_ns(root):
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def inspect_poms(project, group, artifact):
    out = []
    for pom in glob.glob(os.path.join(project, "**", "pom.xml"), recursive=True):
        rel = os.path.relpath(pom, project)
        if any(part in SKIP_DIRS for part in rel.split(os.sep)):
            continue
        try:
            root = _strip_ns(ET.parse(pom).getroot())
        except ET.ParseError:
            continue
        props_el = root.find("properties")
        props = {p.tag: (p.text or "").strip() for p in props_el} if props_el is not None else {}
        info = {"pom": rel.replace(os.sep, "/"), "declared_in": [], "properties": props}
        parent = root.find("parent")
        if parent is not None:
            info["parent"] = ":".join((parent.findtext(t) or "").strip() for t in ("groupId", "artifactId", "version"))
        info["boms_imported"] = [
            f"{d.findtext('groupId')}:{d.findtext('artifactId')}:{d.findtext('version')}"
            for d in root.findall("./dependencyManagement/dependencies/dependency") if d.findtext("scope") == "import"]
        for section, xp in (("dependencies", "./dependencies/dependency"),
                            ("dependencyManagement", "./dependencyManagement/dependencies/dependency"),
                            ("pluginDependencies", ".//plugin/dependencies/dependency")):
            for d in root.findall(xp):
                if (d.findtext("groupId") or "").strip() == group and (d.findtext("artifactId") or "").strip() == artifact:
                    ver = (d.findtext("version") or "").strip() or None
                    prop = re.fullmatch(r"\$\{(.+)\}", ver) if ver else None
                    info["declared_in"].append({
                        "section": section, "version": ver,
                        "property": prop.group(1) if prop else None,
                        "property_value": props.get(prop.group(1)) if prop else None,
                        "property_shared_with": _count_prop_uses(pom, prop.group(1)) - 1 if prop else 0,
                    })
        if info["declared_in"] or info.get("boms_imported") or info.get("parent"):
            out.append(info)
    return out


def _count_prop_uses(pom, prop):
    with open(pom, encoding="utf-8") as fh:
        return fh.read().count("${" + prop + "}")


def run_maven_tree(project):
    exe = shutil.which("mvnw.cmd" if os.name == "nt" else "mvnw", path=project) or shutil.which("mvn")
    if not exe:
        return None, "mvn not found on PATH"
    wrapper = os.path.join(project, "mvnw.cmd" if os.name == "nt" else "mvnw")
    if os.path.exists(wrapper):
        exe = wrapper
    proc = subprocess.run([exe, "-B", "-ntp", "dependency:tree", "-Dverbose=false"], cwd=project,
                          capture_output=True, text=True, timeout=900)
    if proc.returncode != 0:
        return None, "mvn dependency:tree failed:\n" + (proc.stdout + proc.stderr)[-1500:]
    return proc.stdout, None


def trace_maven(project, package, tree_file, fixed):
    if ":" in package:
        group, artifact = package.split(":", 1)
    else:
        group, artifact = None, package
    text, err = (open(tree_file, encoding="utf-8", errors="replace").read(), None) if tree_file else run_maven_tree(project)
    result = {"ecosystem": "maven", "package": package}
    if err:
        result["tree_error"] = err
        result["hint"] = "run `mvn dependency:tree -DoutputFile=tree.txt` yourself and pass --tree tree.txt"
    instances = []
    for n in parse_maven_tree(text or ""):
        if n["artifact"] != artifact or (group and n["group"] != group):
            continue
        group = group or n["group"]
        instances.append({
            "version": n["version"], "scope": n["scope"], "direct": n["depth"] == 1,
            "shortest_chain": n["path"],
            "dependents": [n["path"][-2]] if len(n["path"]) > 1 else [],
        })
    # de-duplicate identical chains from multi-module output
    seen, uniq = set(), []
    for i in instances:
        k = tuple(i["shortest_chain"])
        if k not in seen:
            seen.add(k)
            uniq.append(i)
    result["instances"] = uniq
    if group:
        result["poms"] = inspect_poms(project, group, artifact)
    if not uniq and not err:
        result["summary"] = "artifact not in the resolved tree (check the right module / profile, or it is provided at runtime)"
    else:
        result["summary"] = "; ".join(
            f"{i['version']} ({'direct' if i['direct'] else 'transitive'}, scope {i['scope']})"
            + ("" if i["direct"] else " via " + " > ".join(i["shortest_chain"][1:-1] or ["?"]))
            for i in uniq)
    result["fix_hint"] = _maven_fix_hint(uniq, result.get("poms", []))
    return result


def _maven_fix_hint(instances, poms):
    if any(i["direct"] for i in instances):
        return "direct dependency: bump its <version> (or the property it uses) in the declaring pom"
    for p in poms:
        for d in p["declared_in"]:
            if d["section"] == "dependencyManagement":
                return "already managed: bump the managed version"
    boms = sorted({b for p in poms for b in p.get("boms_imported", [])})
    parents = sorted({p["parent"] for p in poms if p.get("parent")})
    return ("transitive: pin it in <dependencyManagement> of the root pom (wins over imported BOMs"
            + (f" {', '.join(boms)}" if boms else "")
            + (f" and parent {', '.join(parents)}" if parents else "")
            + "), or set the BOM/parent's version property if it exposes one")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ecosystem", choices=["npm", "maven"])
    ap.add_argument("--project", default=".")
    ap.add_argument("--package", required=True)
    ap.add_argument("--fixed", help="version that fixes the vulnerability")
    ap.add_argument("--tree", help="(maven) saved `mvn dependency:tree` output")
    a = ap.parse_args()
    project = os.path.abspath(a.project)
    dump(trace_npm(project, a.package, a.fixed) if a.ecosystem == "npm"
         else trace_maven(project, a.package, a.tree, a.fixed))


if __name__ == "__main__":
    main()
