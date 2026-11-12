# Risk scoring: CVSS, EPSS, CISA KEV

Three different questions. Never collapse them into one number.

| Signal | Answers | Source | Weakness |
|---|---|---|---|
| **CVSS** | How bad *if* exploited (technical severity) | scan, OSV, NVD | Says nothing about likelihood. A 9.8 can be unexploitable in your app. |
| **EPSS** | Probability of exploitation activity in the next 30 days (0-1) plus percentile | api.first.org | Statistical model; new CVEs may have no score yet. 1% is *not* "safe", it is roughly median-ish noise. |
| **CISA KEV** | Is it **actually being exploited** right now | CISA JSON feed | Binary and lagging; absence is not proof of safety. |

## Priority used by `enrich_risk.py`

| Priority | Rule | Typical action |
|---|---|---|
| **P0** | KEV-listed, or EPSS >= 50% | Fix now, out of band. KEV entries carry a CISA due date: report it. |
| **P1** | EPSS >= 10%, or CVSS >= 9.0 with EPSS >= 2% | Fix this sprint. |
| **P2** | CVSS >= 7.0, or EPSS >= 1%, or severity High/Critical | Fix in the normal cycle; may share a PR. |
| **P3** | Everything else | Batch with routine upgrades. |

Example from a real scan: handlebars CVSS 9.8, EPSS 0.8%, KEV no => **P2** (pipeline says
"Critical", but exploitation likelihood is low). Still fix, but do not treat as an incident.

## Adjust with exposure (done by you, using `check_usage.py` and the advisory text)

Priority is a *starting point*. State any adjustment and why:

- **Raise** when: the vulnerable API is called with attacker-influenced data; the service is
  internet-facing (approuter/public endpoint); runtime (not dev/test) dependency; a public PoC exists.
- **Lower** when: dev-only (`"dev": true` in the lockfile, `test`/`provided` scope); the advisory's
  precondition clearly does not hold (e.g. "only applies if untrusted AST is passed to compile()"
  and the code only compiles static strings); the vulnerable component is not on the runtime classpath.
- Never lower below P2 on the *argument* "we don't call it" for a transitive package alone:
  library internals may call it. Say "not obviously reachable" and still schedule the fix.

## Data-quality rules

- Prefer live values over pasted ones and report disagreement (the script does).
- If EPSS or KEV could not be fetched: say **unknown**, never "not listed" / "low".
- CVSS v4 vectors are not computed locally; use the scan/NVD number.
- Several CVEs on one package: take the **max** EPSS, and any KEV hit makes the finding P0.
- GHSA-only advisories (no CVE) have no EPSS/KEV: rely on CVSS + exposure and say so.
