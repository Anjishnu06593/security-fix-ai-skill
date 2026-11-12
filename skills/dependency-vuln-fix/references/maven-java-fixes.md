# Maven / Java fix playbook (including CAP Java)

## 1. Locate the dependency

`scripts/trace_dependency.py maven --project . --package <group:artifact> [--tree tree.txt]`
runs (or reads) `mvn dependency:tree` and inspects every `pom.xml` for where the artifact is
declared: `dependencies`, `dependencyManagement`, a `${property}`, the `<parent>`, or an imported BOM.

Save a tree yourself when mvn is slow or needs a profile:
`mvn -B -ntp dependency:tree -DoutputFile=tree.txt [-P <profile>] [-pl <module> -am]`

## 2. Pick the edit (smallest effective one)

| Situation | Fix | `apply_fix.py maven --mode` |
|---|---|---|
| **Direct** dependency with literal `<version>` | bump it | `bump` |
| **Direct**, version is `${prop}` used only here | bump the property | `bump` (refuses shared props unless `--allow-shared-property`) |
| Version managed by a BOM/parent, fix needs only this artifact | add an entry to the root `<dependencyManagement>` | `manage` |
| Parent/BOM exposes a version property for it (Spring Boot: `snakeyaml.version`, `jackson-bom.version`, `tomcat.version`, `log4j2.version`, `logback.version`, `netty.version`, ...) | set that property in the root pom `<properties>` | `property --property <name>` |
| Fix arrives with a newer parent/BOM release (Spring Boot patch, CAP `cds.services.version`) | bump the parent/BOM | edit manually; run full tests (many artifacts move together) |

Why `manage` works: an entry declared in the project's own `<dependencyManagement>` beats versions
from the parent **and** from imported BOMs (`<scope>import</scope>`). Order inside the section
does not matter. Multi-module: put it in the **root/aggregator** pom so all modules inherit it.

Prefer in this order: (1) bump the BOM/parent if a patch release exists and the project is
otherwise current, (2) Spring Boot property, (3) `manage` entry, (4) direct bump. The later
options are narrower; the earlier ones remove more debt but touch more artifacts.

Anti-patterns:
- `<exclusions>` to drop a vulnerable transitive without adding a fixed one: it may break at
  runtime (NoClassDefFoundError) because the parent needs it.
- Adding the artifact as a *direct* dependency just to pin it: works, but hides intent and leaves a
  stale pin. Use `dependencyManagement`.
- Bumping a shared property (`jackson.version`) when only one artifact needs the fix.

## 3. Choose the version

`scripts/find_safe_version.py maven --package g:a --current X --fixed Y` returns the smallest
stable, OSV-clean version. Additionally:

- Same-major patch/minor first. A major (e.g. SnakeYAML 1.x -> 2.x, Jackson, Spring) needs the
  migration guide and a user decision.
- Check Java baseline (`jdk.version` / `maven.compiler.release`) vs the artifact's requirement.
- Spring Boot managed versions are curated to work together: overriding one component far from the
  managed version (e.g. Tomcat minor jump) can break Boot; prefer the Boot patch release.
- Check that other consumers of the artifact in the tree still work (`dependency:tree` after).

## 4. Verify

```
mvn -B -ntp dependency:tree -Dincludes=<g:a>     # resolved version(s) must be >= fixed
mvn -B -ntp verify                               # compiles, unit + integration tests
mvn -B -ntp dependency:analyze                   # optional: new unused/undeclared warnings
```
`scripts/verify.py maven ...` runs both and records logs. For CAP Java also start the app
once if there are no integration tests (`mvn spring-boot:run`) and hit a health/service endpoint.

Useful extras: `mvn versions:display-dependency-updates`, enforcer rules
`dependencyConvergence` / `requireUpperBoundDeps` to catch downgrades.

## 5. Gradle (not auto-edited)

```groovy
dependencies {
    constraints {
        implementation('org.yaml:snakeyaml:2.2') { because 'GHSA-xxxx / CVE-yyyy' }
    }
}
// last resort, forces everywhere incl. plugins:
configurations.configureEach { resolutionStrategy.force 'org.yaml:snakeyaml:2.2' }
```
Check with `gradle dependencyInsight --dependency snakeyaml --configuration runtimeClasspath`.

## 6. Special cases

- **Shaded/fat JARs** (maven-shade, spring-boot repackage with nested libs): scanners may see a
  bundled copy; the fix is still the declared dependency version.
- **Provided/test scope**: lower exposure (not shipped); still fix, may batch. Say so.
- **Plugin dependencies** (`<plugin><dependencies>`): build-time only; fix there, not in project deps.
- **Private Artifactory mirror**: `find_safe_version.py --maven-repo <url>` or `MAVEN_REPO`.
- **No fixed release**: alternative artifact, vendor patch/backport branch, or risk acceptance
  (dismissal is the user's decision).
