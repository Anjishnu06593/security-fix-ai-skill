# npm / Node.js fix playbook (including CAP Node.js)

Decision order: **cheapest, safest change that makes the resolved version >= fixed.**

## 1. Is the vulnerable package direct or transitive?

`scripts/trace_dependency.py npm --project . --package <pkg> --fixed <ver>` reports per installed copy:
direct/transitive, dev-only, shortest chain, each dependent's declared range, and
`range_allows_fixed`.

| Situation | Fix | Command / edit |
|---|---|---|
| **Direct**, fix within range | Refresh lock | `npm update <pkg>` |
| **Direct**, range excludes fix | Bump range | edit `dependencies` -> `^<fixed>` (`apply_fix.py npm --strategy direct`) |
| **Transitive**, every dependent's range allows the fix (`lock_refresh_may_suffice`) | Refresh lock only | `npm update <pkg> --package-lock-only` (`--strategy lock-refresh`) |
| **Transitive**, parent publishes a newer release that allows the fix | Bump the *parent* (best: removes the problem at source) | `npm install <parent>@<ver>`; check `npm view <parent> dependencies` |
| **Transitive**, parent pins/excludes the fix and has no newer release | `overrides` | `apply_fix.py npm --strategy override` (scope with `--parent` when possible) |
| Package is dev-only and the project ships no build artefact from it | Lower priority, still fix, may batch | same as above |

Avoid `npm audit fix --force`: it accepts semver-major upgrades blindly (a hook asks first).
Plain `npm audit fix` is acceptable *only* after reading its diff; it stays within ranges.

## 2. overrides, resolutions, pnpm

- npm (>=8.3): `"overrides": {"pkg": "^4.7.10"}`; scoped: `"overrides": {"parent": {"pkg": "^4.7.10"}}`;
  a package that is also an override target of its own children uses `"."` key.
- **EOVERRIDE**: npm errors if an override conflicts with a *direct* dependency range. Fix the direct
  range, or set the override to `"$pkg"` to reference it.
- yarn classic/berry: `"resolutions"`; pnpm: `"pnpm": {"overrides": {...}}` (`parent>pkg` for scoping).
- Overrides live **only in the root package.json**. In workspaces, ancestors' overrides are ignored.
- Use a caret range (`^x.y.z`) so later patch fixes still flow; pin exact only if the user asks.
- Leave a breadcrumb: note in the PR which advisory the override exists for, so it can be removed once
  the parent catches up. (JSON has no comments; put it in the PR description / report.)

## 3. Lockfile hygiene

- Always regenerate via npm; never hand-edit `package-lock.json`.
- After changes, `npm ci` must pass: the pipeline and `mta build` use it and **fail when
  package.json and the lockfile disagree**.
- `npm install --package-lock-only --ignore-scripts` updates the lock without touching node_modules
  or running install scripts (safer for a security task).
- Keep the lockfile version stable (`lockfileVersion`): do not let a different npm major rewrite the
  whole file. Check `git diff --stat package-lock.json`; a huge diff means the wrong npm version ran.
- Private registry / proxy: honour `.npmrc`; do not add public registry URLs.

## 4. Choosing the version

`scripts/find_safe_version.py npm ...` encodes: >= fixed, stable, not deprecated, OSV-clean,
smallest bump (patch < minor < major). Then still check:

- Changelog/release notes between current and target (`npm view <pkg> repository.url`).
- `engines.node` against the runtime Node version (mta.yaml `nodejs_buildpack`, `.nvmrc`, `package.json engines`).
- `peerDependencies` of the target against what the project provides.
- Brand-new releases (< a few days): flag them; supply-chain attacks hit fresh versions.
- Major bump: require explicit user approval, and a migration read-through first.

## 5. Special cases

- **No fix exists / maintainer abandoned**: options in order: alternative package; vendor patch via
  `patch-package` (user must agree to maintaining it); upgrade parent that dropped the dependency;
  documented risk acceptance (GitLab: dismiss with reason, **user does this**, never the skill).
- **Fix only in a new major that the parent does not support**: override *can* force it but may break
  the parent at runtime. Run the tests and call out the risk explicitly.
- **Bundled/vendored copies** (e.g. inside `@sap/*` or a `dist/`): scans may flag a bundled copy that
  overrides cannot change. Then the fix is a newer version of the bundling package.
- **Multiple lockfiles** (root + `srv/` + `app/*/`): each lockfile is scanned separately; fix the one
  named in the finding's `File` field, and check the others for the same package.
- **Native modules / install scripts**: keep `--ignore-scripts` on analysis steps.
