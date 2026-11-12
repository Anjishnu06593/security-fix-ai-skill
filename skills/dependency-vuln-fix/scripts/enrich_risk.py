#!/usr/bin/env python3
"""Enrich normalized findings with CVSS, EPSS, CISA KEV and fixed-version data.

Sources (all public, no API key):
  * OSV.dev            https://api.osv.dev            CVSS vector, affected ranges, fixed versions
  * FIRST EPSS         https://api.first.org/data/v1/epss
  * CISA KEV catalog   https://www.cisa.gov/known-exploited-vulnerabilities-catalog (JSON feed)

Usage:
  parse_findings.py -f scan.json | enrich_risk.py            (stdin -> stdout)
  enrich_risk.py --file findings.json [--offline]

Network failures never abort: the field is left null and listed in
`risk.unavailable` so the caller can ask the user or fall back to web search.
Values already present on a finding (e.g. pasted from GitLab) are kept and
cross-checked; disagreements are reported in `risk.notes`.
"""
import argparse
import json
import sys
from datetime import datetime, timezone

sys.path.insert(0, __import__("os").path.dirname(__file__))
from common import (  # noqa: E402
    cvss3_score, dump, eprint, http, read_input, semver_cmp, maven_cmp, severity_from_cvss,
)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={ids}"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_ECOSYSTEM = {"npm": "npm", "maven": "Maven"}


def osv_fetch(finding):
    """Return the best-matching OSV record for a finding, or None."""
    for vid in finding["ghsas"] + finding["cves"]:
        try:
            return http(OSV_VULN.format(id=vid), ttl=6 * 3600)
        except RuntimeError:
            continue
    if finding["package"] and finding["version"]:
        eco = OSV_ECOSYSTEM.get(finding["ecosystem"], finding["ecosystem"])
        try:
            res = http(OSV_QUERY, body={"version": finding["version"],
                                        "package": {"name": finding["package"], "ecosystem": eco}}, ttl=6 * 3600)
        except RuntimeError:
            return None
        wanted = set(finding["ghsas"] + finding["cves"])
        for v in res.get("vulns", []):
            if wanted & ({v.get("id")} | set(v.get("aliases", []))):
                return v
    return None


def osv_fixed(record, finding):
    """Collect fixed versions from OSV `affected`; pick the one covering the installed version."""
    cmp_ = maven_cmp if finding["ecosystem"] == "maven" else semver_cmp
    name = finding["package"]
    fixed_all, covering = set(), None
    for aff in record.get("affected", []):
        pkg = (aff.get("package") or {}).get("name")
        if pkg and name and pkg.lower() != name.lower():
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            introduced = None
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    introduced = ev["introduced"]
                elif "fixed" in ev:
                    fixed_all.add(ev["fixed"])
                    cur = finding["version"]
                    if cur and (introduced in (None, "0") or cmp_(cur, introduced) >= 0) and cmp_(cur, ev["fixed"]) < 0:
                        if covering is None or cmp_(ev["fixed"], covering) < 0:
                            covering = ev["fixed"]
    return sorted(fixed_all, key=lambda v: _key(v, finding)), covering


def _key(v, finding):
    from functools import cmp_to_key
    return cmp_to_key(maven_cmp if finding["ecosystem"] == "maven" else semver_cmp)(v)


def load_kev(offline):
    if offline:
        return None
    try:
        data = http(KEV_URL, ttl=12 * 3600, timeout=40)
    except RuntimeError as exc:
        eprint(f"[warn] KEV unavailable: {exc}")
        return None
    return {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}


def load_epss(cves, offline):
    if offline or not cves:
        return {}
    out = {}
    for i in range(0, len(cves), 50):
        chunk = cves[i:i + 50]
        try:
            res = http(EPSS_URL.format(ids=",".join(chunk)), ttl=6 * 3600)
        except RuntimeError as exc:
            eprint(f"[warn] EPSS unavailable: {exc}")
            return out
        for row in res.get("data", []):
            out[row["cve"].upper()] = (float(row["epss"]), float(row["percentile"]), row.get("date"))
    return out


def prioritize(cvss, epss, kev, severity):
    """Return (priority, rationale). P0 = fix now ... P3 = batch with routine upgrades."""
    why = []
    if kev:
        return "P0", ["listed in CISA KEV: exploited in the wild"]
    if epss is not None and epss >= 0.5:
        return "P0", [f"EPSS {epss:.0%}: very likely to be exploited"]
    if (epss is not None and epss >= 0.1) or (cvss is not None and cvss >= 9.0 and (epss is None or epss >= 0.02)):
        if epss is not None and epss >= 0.1:
            why.append(f"EPSS {epss:.0%} (>=10%)")
        if cvss is not None and cvss >= 9.0:
            why.append(f"CVSS {cvss} (critical)")
        return "P1", why
    if (cvss is not None and cvss >= 7.0) or (epss is not None and epss >= 0.01) or severity in ("Critical", "High"):
        if cvss is not None:
            why.append(f"CVSS {cvss}")
        if epss is not None:
            why.append(f"EPSS {epss:.1%}")
        return "P2", why or ["high severity, low exploit likelihood"]
    return "P3", [f"CVSS {cvss}" if cvss is not None else "low severity", "low exploit likelihood"]


def enrich(findings, offline=False):
    kev = load_kev(offline)
    all_cves = sorted({c for f in findings for c in f["cves"]})
    epss = load_epss(all_cves, offline)
    for f in findings:
        risk = {"unavailable": [], "notes": []}
        record = None if offline else osv_fetch(f)
        if record is None and not offline:
            risk["unavailable"].append("osv")

        # --- CVSS
        cvss, vector = f.get("cvss"), f.get("cvss_vector")
        if record:
            for sev in record.get("severity", []):
                if sev.get("type", "").startswith("CVSS_V3"):
                    vector = vector or sev.get("score")
            calc = cvss3_score(vector)
            if calc is not None:
                if cvss is not None and abs(calc - cvss) > 0.05:
                    risk["notes"].append(f"scan CVSS {cvss} differs from OSV vector score {calc}; using scan value")
                cvss = cvss if cvss is not None else calc
        risk["cvss"], risk["cvss_vector"] = cvss, vector

        # --- EPSS
        e = None
        for c in f["cves"]:
            if c in epss:
                e = max(e or (0, 0, None), epss[c], key=lambda t: t[0])
        if e:
            if f.get("epss") is not None and abs(f["epss"] - e[0]) > 0.02:
                risk["notes"].append(f"scan EPSS {f['epss']:.1%} differs from live EPSS {e[0]:.1%}; using live value")
            risk["epss"], risk["epss_percentile"], risk["epss_date"] = e[0], e[1], e[2]
        else:
            risk["epss"], risk["epss_percentile"], risk["epss_date"] = f.get("epss"), None, None
            if f["cves"] and not offline and f.get("epss") is None:
                risk["unavailable"].append("epss (no score published yet or lookup failed)")

        # --- KEV
        if kev is not None:
            hits = [kev[c] for c in f["cves"] if c in kev]
            risk["kev"] = bool(hits)
            if hits:
                risk["kev_detail"] = {"due_date": hits[0].get("dueDate"),
                                      "ransomware": hits[0].get("knownRansomwareCampaignUse"),
                                      "required_action": hits[0].get("requiredAction")}
        else:
            risk["kev"] = f.get("kev")
            if not offline:
                risk["unavailable"].append("kev")
            if f.get("kev") is None and f["cves"]:
                risk["notes"].append("KEV status unknown: do not assume 'not listed'")

        # --- fixed versions
        fixed_all, covering = ([], None)
        if record:
            fixed_all, covering = osv_fixed(record, f)
            risk["osv_id"] = record.get("id")
            risk["aliases"] = record.get("aliases", [])
            risk["summary"] = record.get("summary")
            if not f["cves"]:
                f["cves"] = sorted(a for a in record.get("aliases", []) if a.startswith("CVE-"))
        risk["fixed_versions"] = fixed_all
        risk["min_fixed_for_installed"] = covering or f.get("fixed_hint")
        if f.get("fixed_hint") and covering and f["fixed_hint"] != covering:
            risk["notes"].append(f"scan says fix {f['fixed_hint']} but OSV says {covering}; verify against the advisory")

        sev = f.get("severity") or severity_from_cvss(cvss)
        risk["priority"], risk["rationale"] = prioritize(cvss, risk.get("epss"), risk.get("kev"), sev)
        risk["enriched_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        f["risk"] = risk
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    findings.sort(key=lambda x: (order[x["risk"]["priority"]], -(x["risk"].get("cvss") or 0)))
    return findings


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", "-f", default="-")
    ap.add_argument("--offline", action="store_true", help="skip all network lookups")
    args = ap.parse_args()
    data = json.loads(read_input(args.file))
    data["findings"] = enrich(data["findings"], args.offline)
    dump(data)


if __name__ == "__main__":
    main()
