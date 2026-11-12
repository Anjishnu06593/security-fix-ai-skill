#!/usr/bin/env python3
"""Normalize vulnerability findings from many sources into one JSON shape.

Accepted input (auto-detected):
  * GitLab dependency-scanning report   (gl-dependency-scanning-report.json)
  * GitLab vulnerability API / GraphQL  (list or {"nodes": [...]})
  * GitHub Dependabot alerts API        (list of alert objects)
  * `npm audit --json`
  * Text pasted from the GitLab/GitHub vulnerability page (one or many findings)

Usage:
  parse_findings.py [--file PATH | -] [--ecosystem npm|maven]
Output: {"source_format": ..., "findings": [ {...normalized...} ]}
"""
import argparse
import json
import re
import sys

sys.path.insert(0, __import__("os").path.dirname(__file__))
from common import dump, read_input, severity_from_cvss  # noqa: E402

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.I)
NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "package.json")
MVN_FILES = ("pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile")


def infer_ecosystem(file_, name, hint=None):
    f = (file_ or "").lower()
    if f.endswith(NPM_LOCKS):
        return "npm"
    if f.endswith(MVN_FILES):
        return "maven"
    if name and ":" in name and not name.startswith("@"):
        return "maven"
    return hint or "npm"


def blank():
    return {
        "id": None, "title": None, "package": None, "version": None, "ecosystem": None,
        "file": None, "branch": None, "severity": None, "cvss": None, "cvss_vector": None,
        "epss": None, "kev": None, "cves": [], "ghsas": [], "other_ids": [], "cwes": [],
        "fixed_hint": None, "solution_text": None, "reachability": None, "links": [],
        "description": None, "source": None,
    }


def finish(f, hint):
    f["cves"] = sorted({c.upper() for c in f["cves"]})
    f["ghsas"] = sorted({"GHSA-" + g[5:].lower() for g in f["ghsas"] if g[:5].upper() == "GHSA-"})
    f["ecosystem"] = f["ecosystem"] or infer_ecosystem(f["file"], f["package"], hint)
    if f["severity"]:
        f["severity"] = f["severity"].capitalize()
    elif f["cvss"] is not None:
        f["severity"] = severity_from_cvss(f["cvss"])
    return f


# --------------------------------------------------------------------------- JSON sources

def _ids_from_identifiers(f, identifiers):
    for ident in identifiers or []:
        val = str(ident.get("value") or ident.get("externalId") or ident.get("name") or "")
        typ = str(ident.get("type") or ident.get("externalType") or "").lower()
        if typ == "cve" or CVE_RE.fullmatch(val):
            f["cves"].append(val)
        elif typ == "ghsa" or GHSA_RE.fullmatch(val):
            f["ghsas"].append(val)
        elif typ == "cwe":
            f["cwes"].append(val if val.upper().startswith("CWE") else f"CWE-{val}")
        elif val:
            f["other_ids"].append(val)


def from_gitlab(v, hint):
    f = blank()
    f["source"] = "gitlab"
    f["id"] = v.get("id") or v.get("uuid")
    f["title"] = v.get("name") or v.get("title") or v.get("message")
    f["description"] = v.get("description")
    f["severity"] = v.get("severity")
    f["solution_text"] = v.get("solution")
    loc = v.get("location") or {}
    dep = loc.get("dependency") or {}
    pkg = (dep.get("package") or {}).get("name")
    f["package"], f["version"], f["file"] = pkg, dep.get("version"), loc.get("file")
    _ids_from_identifiers(f, v.get("identifiers"))
    f["links"] = [l.get("url") if isinstance(l, dict) else l for l in v.get("links") or []]
    if v.get("cvss_vectors"):
        f["cvss_vector"] = (v["cvss_vectors"][0] or {}).get("vector")
    m = re.search(r"[Uu]pgrade to (?:version )?([\w.\-]+)", f["solution_text"] or "")
    f["fixed_hint"] = m.group(1) if m else None
    return finish(f, hint)


def from_dependabot(a, hint):
    f = blank()
    f["source"] = "github-dependabot"
    adv = a.get("security_advisory") or {}
    vul = a.get("security_vulnerability") or {}
    pkg = vul.get("package") or (a.get("dependency") or {}).get("package") or {}
    f["id"] = a.get("number")
    f["title"] = adv.get("summary")
    f["description"] = adv.get("description")
    f["package"] = pkg.get("name")
    eco = (pkg.get("ecosystem") or "").lower()
    f["ecosystem"] = {"npm": "npm", "maven": "maven"}.get(eco, eco or None)
    f["file"] = (a.get("dependency") or {}).get("manifest_path")
    f["severity"] = adv.get("severity") or vul.get("severity")
    f["cvss"] = (adv.get("cvss") or {}).get("score") or None
    f["cvss_vector"] = (adv.get("cvss") or {}).get("vector_string")
    if adv.get("ghsa_id"):
        f["ghsas"].append(adv["ghsa_id"])
    if adv.get("cve_id"):
        f["cves"].append(adv["cve_id"])
    f["cwes"] = [c.get("cwe_id") for c in adv.get("cwes") or [] if c.get("cwe_id")]
    f["fixed_hint"] = (vul.get("first_patched_version") or {}).get("identifier")
    f["solution_text"] = f"Vulnerable range: {vul.get('vulnerable_version_range')}"
    f["links"] = [r.get("url") for r in adv.get("references") or [] if r.get("url")]
    return finish(f, hint)


def from_npm_audit(data, hint):
    out = []
    for name, v in (data.get("vulnerabilities") or {}).items():
        for via in v.get("via") or []:
            if not isinstance(via, dict):
                continue  # string = reached through another package, covered there
            f = blank()
            f["source"] = "npm-audit"
            f["title"] = via.get("title")
            f["package"] = via.get("name") or name
            f["ecosystem"] = "npm"
            f["severity"] = via.get("severity")
            f["cvss"] = (via.get("cvss") or {}).get("score") or None
            f["cvss_vector"] = (via.get("cvss") or {}).get("vectorString")
            url = via.get("url") or ""
            f["links"] = [url] if url else []
            f["ghsas"] += GHSA_RE.findall(url)
            f["cwes"] = via.get("cwe") or []
            fa = v.get("fixAvailable")
            if isinstance(fa, dict):
                f["fixed_hint"] = fa.get("version")
                f["solution_text"] = (
                    f"npm audit fix target {fa.get('name')}@{fa.get('version')}"
                    + (" (semver-major)" if fa.get("isSemVerMajor") else "")
                )
            f["version"] = None  # npm audit gives ranges, not the installed version
            f["description"] = f"Affected range: {via.get('range')}"
            out.append(finish(f, "npm"))
    return out


# --------------------------------------------------------------------------- pasted text

MARKER = re.compile(r"^\s*Vulnerability Report\s*$", re.M)


def _grab(pattern, text, flags=re.I | re.M):
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else None


def parse_text_block(block, hint):
    f = blank()
    f["source"] = "pasted-text"
    lines = [l.strip() for l in block.splitlines() if l.strip()]
    marker_seen = False
    for l in lines:
        if re.fullmatch(r"Vulnerability Report", l, re.I):
            marker_seen = True
            continue
        if marker_seen and not l.isdigit() and len(l) >= 15 and not l.lower().startswith("detected"):
            f["title"] = l
            break
    if not f["title"]:
        f["title"] = next((l for l in lines if len(l) >= 15), None)
    f["id"] = next((l for l in lines if l.isdigit() and len(l) >= 6), None)
    # ids in the title may name a *different* CVE ("bypass of CVE-..."), so prefer the Identifiers section
    ident = _grab(r"^\s*Identifiers\s*\n(.+?)(?:\n\s*Links\s*\n|\n\s*Evidence\s*\n|\Z)", block, re.I | re.S | re.M)
    f["cves"] = CVE_RE.findall(ident or block)
    f["ghsas"] = GHSA_RE.findall(ident or block)
    f["cwes"] = sorted(set(re.findall(r"\bCWE-\d+\b", block)))
    f["links"] = re.findall(r"https?://\S+", block)
    f["branch"] = _grab(r"^\s*Branch\s*(\S+)", block)
    f["file"] = _grab(r"^\s*File\s*\n?\s*(\S+)", block)
    sev = _grab(r"^\s*(Critical|High|Medium|Low|Info|Unknown)\s*$", block)
    f["severity"] = sev
    score = _grab(r"CVSS score\s*\n?\s*(?:v?\d(?:\.\d)?\s*:\s*)?(\d+(?:\.\d+)?)", block)
    f["cvss"] = float(score) if score else None
    epss = _grab(r"EPSS\s*\n?\s*(\d+(?:\.\d+)?)\s*%", block)
    f["epss"] = float(epss) / 100 if epss else None
    kev = _grab(r"KEV listed\s*\n?\s*(Yes|No)", block)
    f["kev"] = None if kev is None else kev.lower() == "yes"
    f["reachability"] = _grab(r"^\s*Reachability\s*\n?\s*(.+)$", block)
    f["solution_text"] = _grab(r"^\s*Remediation\s*\n\s*(.+)$", block) or _grab(r"(Upgrade to .+)$", block)
    m = re.search(r"[Uu]pgrade to (?:version )?([\w.\-]+)(?: or above)?", f["solution_text"] or "")
    f["fixed_hint"] = m.group(1) if m else None
    m = re.search(r"Vulnerable Package\s*\n\s*([^\s:]+(?::[^\s:]+)?):(\d[^\s:]*)\s*$", block, re.M)
    if not m:  # free form: "lodash@4.17.20" or "org.x:y:1.2.3"
        m = re.search(r"([@\w./\-]+(?::[\w.\-]+)?)[@:](\d+\.\d[\w.\-]*)", block)
    if m:
        f["package"], f["version"] = m.group(1), m.group(2)
    desc = _grab(r"^\s*Description\s*\n(.+?)(?:\n\s*Supplementary information|\Z)", block, re.I | re.S | re.M)
    f["description"] = desc
    return finish(f, hint)


def parse_text(text, hint):
    if MARKER.search(text):
        chunks = re.split(r"(?m)^(?=\s*Vulnerability Report\s*$)", text)
        chunks = [c for c in chunks if MARKER.search(c)]
    else:
        chunks = [text]
    return [parse_text_block(c, hint) for c in chunks]


# --------------------------------------------------------------------------- dispatch

def parse(text, hint=None):
    stripped = text.lstrip()
    if stripped[:1] in "[{":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"input looks like JSON but is invalid: {exc}")
        if isinstance(data, dict) and "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
            return "gitlab-report", [from_gitlab(v, hint) for v in data["vulnerabilities"]]
        if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), dict):
            return "npm-audit", from_npm_audit(data, hint)
        items = data.get("nodes") if isinstance(data, dict) and "nodes" in data else data
        items = items if isinstance(items, list) else [items]
        if items and isinstance(items[0], dict) and "security_advisory" in items[0]:
            return "github-dependabot", [from_dependabot(a, hint) for a in items]
        return "gitlab-api", [from_gitlab(v, hint) for v in items]
    return "text", parse_text(text, hint)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", "-f", default="-", help="input file, or - for stdin")
    ap.add_argument("--ecosystem", choices=["npm", "maven"], help="fallback ecosystem when it cannot be inferred")
    args = ap.parse_args()
    fmt, findings = parse(read_input(args.file), args.ecosystem)
    findings = [f for f in findings if f["package"] or f["title"]]
    dump({"source_format": fmt, "count": len(findings), "findings": findings})


if __name__ == "__main__":
    main()
