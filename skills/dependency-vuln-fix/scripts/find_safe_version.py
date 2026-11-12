#!/usr/bin/env python3
"""Pick the lowest *stable* version that fixes a vulnerability without needless risk.

Rules (in order): at or above the minimum fixed version; no prerelease/snapshot;
not deprecated (npm); no known vulnerabilities left in that exact version (OSV);
prefer the smallest jump (patch < minor < major), then the lowest version.
Fresh releases (< --min-age-days, npm only) are flagged, not silently chosen.

Usage:
  find_safe_version.py npm   --package handlebars --current 4.7.9 --fixed 4.7.10
  find_safe_version.py maven --package org.yaml:snakeyaml --current 1.33 --fixed 2.0
Env: NPM_REGISTRY (default https://registry.npmjs.org), MAVEN_REPO (default https://repo1.maven.org/maven2)
"""
import argparse
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from functools import cmp_to_key
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(__file__))
from common import (  # noqa: E402
    bump_kind, dump, http, is_prerelease, maven_cmp, maven_is_stable, parse_semver, semver_cmp,
)

OSV_QUERY = "https://api.osv.dev/v1/query"
KIND_RANK = {"patch": 0, "minor": 1, "major": 2, "unknown": 3}


def npm_versions(package, registry):
    doc = http(f"{registry.rstrip('/')}/{quote(package, safe='@')}", ttl=1800, timeout=40)
    times = doc.get("time", {})
    out = []
    for ver, meta in doc.get("versions", {}).items():
        out.append({"version": ver, "deprecated": meta.get("deprecated"), "published": times.get(ver),
                    "engines": meta.get("engines"), "peer": meta.get("peerDependencies")})
    return out, doc.get("dist-tags", {})


def maven_versions(package, repo):
    group, artifact = package.split(":", 1)
    url = f"{repo.rstrip('/')}/{group.replace('.', '/')}/{artifact}/maven-metadata.xml"
    root = ET.fromstring(http(url, ttl=1800, as_text=True, timeout=40, headers={"Accept": "application/xml"}))
    vers = [v.text for v in root.findall("./versioning/versions/version")]
    return [{"version": v, "deprecated": None, "published": None} for v in vers], {
        "latest": (root.findtext("./versioning/latest") or ""), "release": (root.findtext("./versioning/release") or "")}


def remaining_vulns(ecosystem, package, version):
    eco = {"npm": "npm", "maven": "Maven"}[ecosystem]
    try:
        res = http(OSV_QUERY, body={"version": version, "package": {"name": package, "ecosystem": eco}}, ttl=6 * 3600)
    except RuntimeError:
        return None  # unknown
    return sorted({v["id"] for v in res.get("vulns", [])})


def age_days(published):
    if not published:
        return None
    try:
        dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - dt).days


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ecosystem", choices=["npm", "maven"])
    ap.add_argument("--package", required=True)
    ap.add_argument("--current", required=True, help="installed (vulnerable) version")
    ap.add_argument("--fixed", required=True, help="minimum version that fixes the advisory")
    ap.add_argument("--max-check", type=int, default=6, help="how many candidates to vuln-check against OSV")
    ap.add_argument("--min-age-days", type=int, default=3)
    ap.add_argument("--registry", default=os.environ.get("NPM_REGISTRY", "https://registry.npmjs.org"))
    ap.add_argument("--maven-repo", default=os.environ.get("MAVEN_REPO", "https://repo1.maven.org/maven2"))
    a = ap.parse_args()

    cmp_ = maven_cmp if a.ecosystem == "maven" else semver_cmp
    stable = maven_is_stable if a.ecosystem == "maven" else (lambda v: not is_prerelease(v) and parse_semver(v) is not None)
    try:
        versions, tags = (npm_versions(a.package, a.registry) if a.ecosystem == "npm"
                          else maven_versions(a.package, a.maven_repo))
    except (RuntimeError, ET.ParseError) as exc:
        dump({"error": str(exc), "hint": "registry unreachable (corporate proxy / private registry?). "
              "Set NPM_REGISTRY / MAVEN_REPO or pick the version manually from the advisory."})
        sys.exit(2)

    pool = [v for v in versions if cmp_(v["version"], a.fixed) >= 0 and stable(v["version"])]
    pool.sort(key=cmp_to_key(lambda x, y: cmp_(x["version"], y["version"])))
    for v in pool:
        v["kind"] = bump_kind(a.current, v["version"]) if a.ecosystem == "npm" else _mvn_kind(a.current, v["version"])
        v["age_days"] = age_days(v["published"])
    # pool is ascending, so its index is the version order
    ordered = sorted(pool, key=lambda v: (KIND_RANK[v["kind"]], pool.index(v)))

    checked, recommended, skipped = [], None, []
    for v in ordered[: a.max_check]:
        v["remaining_vulns"] = remaining_vulns(a.ecosystem, a.package, v["version"])
        entry = {k: v[k] for k in ("version", "kind", "deprecated", "age_days", "remaining_vulns")}
        entry["engines"] = v.get("engines")
        checked.append(entry)
        if v["deprecated"]:
            skipped.append(f"{v['version']}: deprecated ({v['deprecated'][:80]})")
        elif v["remaining_vulns"]:
            skipped.append(f"{v['version']}: still affected by {', '.join(v['remaining_vulns'][:5])}")
        elif recommended is None:
            recommended = entry
    notes = []
    if recommended:
        if recommended["kind"] == "major":
            notes.append("MAJOR upgrade: read the migration guide/changelog before applying; ask the user to confirm")
        if recommended["remaining_vulns"] is None:
            notes.append("OSV lookup failed: could not confirm the version is free of other known vulns")
        if recommended.get("age_days") is not None and recommended["age_days"] < a.min_age_days:
            notes.append(f"released {recommended['age_days']} day(s) ago; consider waiting or review the release")
        if recommended.get("engines"):
            notes.append(f"declares engines {recommended['engines']}: check against your Node runtime (mta.yaml / .nvmrc / CF buildpack)")
    else:
        notes.append("no stable, non-deprecated, vuln-free version at or above the fix was found: "
                     "consider an alternative package, a vendor patch, or a documented risk acceptance")
    dump({
        "package": a.package, "ecosystem": a.ecosystem, "current": a.current, "min_fixed": a.fixed,
        "latest_tag": tags.get("latest") or tags.get("release"),
        "candidates_checked": checked, "recommended": recommended, "skipped": skipped, "notes": notes,
    })


def _mvn_kind(current, candidate):
    c = re.findall(r"\d+", current)
    n = re.findall(r"\d+", candidate)
    if not c or not n:
        return "unknown"
    if c[0] != n[0]:
        return "major"
    if len(c) > 1 and len(n) > 1 and c[1] != n[1]:
        return "minor"
    return "patch"


if __name__ == "__main__":
    main()
