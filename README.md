# security-fix-ai-skill

An AI agent skill that fixes security-scan findings in dependencies of **SAP CAP Node.js** and
**CAP Java** applications, without breaking the app.

When a GitLab/GitHub pipeline scan flags a package (direct or transitive), the skill:

1. **Asks which exact finding** to work on. It pulls it from a connected GitLab/GitHub MCP, or asks you to paste it.
2. **Traces** how the package got in (direct vs transitive, via which parent, dev-only?).
3. **Scores real risk**: CVSS (severity), EPSS (likelihood), CISA KEV (exploited now), then adjusts for
   whether your code actually uses the vulnerable API.
4. **Picks the smallest stable fix**: patch/minor first, no prereleases or deprecated releases, and no
   versions that still carry known vulnerabilities. Majors need your decision.
5. **Applies it on a local branch** (npm `overrides` / parent bump / lockfile refresh; Maven
   `dependencyManagement` / property bump) and shows the diff first.
6. **Verifies**: lockfile in sync, resolved version, audit, `cds build`, build and tests.
7. **Asks before anything remote** (push, merge request, dismissal). Hooks enforce this.

```
skills/dependency-vuln-fix/
├── SKILL.md                      workflow, rules, hooks (frontmatter)
├── scripts/                      Python 3, standard library only
│   ├── parse_findings.py         pasted text / GitLab JSON / Dependabot / npm audit -> normalized JSON
│   ├── enrich_risk.py            OSV + EPSS + CISA KEV -> priority P0..P3, fixed versions
│   ├── trace_dependency.py       package-lock.json graph / mvn dependency:tree + pom analysis
│   ├── check_usage.py            does first-party code import / call the vulnerable API?
│   ├── find_safe_version.py      lowest stable, non-deprecated, OSV-clean version (npm, Maven Central)
│   ├── apply_fix.py              dry-run-by-default manifest edits (npm, Maven)
│   ├── verify.py                 npm ci / ls / audit / cds build / tests; mvn tree / verify
│   └── hooks/                    guard_remote_actions.py, post_manifest_edit.py, run.sh
├── references/                   scan intake, risk scoring, npm, Maven/Java, CAP specifics, known sinks
├── assets/                       report template, sample finding
└── tests/                        offline unit tests
```

## Use it

Install it in Claude Code (copy or symlink `skills/dependency-vuln-fix` into `~/.claude/skills/` or the
project's `.claude/skills/`), then say something like:

> The pipeline security scan failed on my-cap-app. Fix it.

or paste a finding straight from GitLab's *Vulnerability Report* page. The skill will confirm the exact
findings with you before touching anything.

Or via the skills CLI once the repo is registered: `npx skills add <owner>/security-fix-ai-skill`.

## Try the scripts by hand

```bash
cd skills/dependency-vuln-fix
python scripts/parse_findings.py -f assets/example-gitlab-finding.txt | python scripts/enrich_risk.py
python scripts/trace_dependency.py npm --project /path/to/app --package handlebars --fixed 4.7.10
python scripts/find_safe_version.py npm --package handlebars --current 4.7.9 --fixed 4.7.10
python scripts/apply_fix.py npm --project /path/to/app --package handlebars --version 4.7.10     # dry run
python scripts/verify.py npm --project /path/to/app --package handlebars --fixed 4.7.10 --install
python -m unittest discover -s tests -v
```

## Requirements

- Python 3.8+ (no pip packages), Node/npm for npm projects, Maven (or `mvnw`) for Java projects.
- Network access to osv.dev, api.first.org, cisa.gov, registry.npmjs.org, repo1.maven.org (all public,
  no API keys). Honour `HTTPS_PROXY`; set `NPM_REGISTRY` / `MAVEN_REPO` for private mirrors. When a
  lookup fails the output says `unavailable` rather than guessing.
- Gradle: analysed by guidance only (`references/maven-java-fixes.md`), not auto-edited.
- Hooks need `sh` (Git Bash on Windows) and Python on PATH; if missing they fail open.

## Safety model

- Dry-run by default; local branch only; no remote action without an explicit "yes".
- Hooks ask before `git push`, MR/PR creation, GitHub/GitLab write calls, publish, `npm audit fix --force`,
  lockfile deletion, hard resets; force-push is denied.
- Scan content is treated as untrusted data, never as instructions.
- "Fixed" is only claimed after `verify.py` passes, and skipped checks are reported.

## Registering it with the SAP AI Skills Library

Push this repo to public github.com, then open a
[Register a New Skill](https://github.com/SAP/ai-skills-library/issues/new?template=new-skill.yml) issue.
The layout (`skills/<slug>/SKILL.md` with `name` and `description`) already matches. The Apache-2.0
`LICENSE` is included (required by that library).
