# Dependency vulnerability fix report

**Project:** <repo / module>  **Branch:** <fix branch> (from <base>)  **Date:** <YYYY-MM-DD>
**Scan source:** <GitLab/GitHub, via MCP | pasted>  **Findings in scope:** <n>

## Summary
| # | Package | From -> To | Type | Priority | CVSS | EPSS | KEV | Fix used | Verified |
|---|---------|-----------|------|----------|------|------|-----|----------|----------|
| 1 | handlebars | 4.7.9 -> 4.7.10 | transitive via hbs | P2 | 9.8 | 0.8% | No | npm override `^4.7.10` | PASS |

## Per finding
### 1. <title> (<CVE / GHSA>)
- **What the scan said:** <package@version, file, remediation text>
- **Real risk:** CVSS <>, EPSS <> (<percentile>), KEV <yes/no/unknown>. Priority <P?> because <rationale>.
- **Exposure in this code:** <check_usage verdict + evidence file:line, or "not obviously used">
- **How it got in:** <direct | chain: a > b > pkg>
- **Options considered:** <parent bump / override / direct bump, with why rejected>
- **Change made:** <file(s), diff summary, bump kind patch/minor/major>
- **Stability checks:** <deprecated? vulns remaining? engines/peer ok? changelog notes>
- **Verification:** <commands + results; link logs> ; **Not verified:** <skipped steps, e.g. no tests>

## Not fixed / needs a decision
- <finding> : <why (no fix, major upgrade, test failure)> : <recommended next step / risk acceptance text>

## Follow-ups
- Overrides to remove once <parent> releases a version allowing <fixed>.
- Re-run the pipeline scan; expected result: findings <ids> resolved.

## Remote actions
Nothing pushed. Awaiting approval to: push branch / open merge request.
