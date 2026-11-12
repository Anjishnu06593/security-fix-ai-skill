"""Offline unit tests (no network). Run: python -m unittest discover -s tests -v"""
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import common  # noqa: E402
import parse_findings  # noqa: E402
import trace_dependency  # noqa: E402
from enrich_risk import prioritize  # noqa: E402


def fixture():
    with open(os.path.join(ROOT, "assets", "example-gitlab-finding.txt"), encoding="utf-8") as fh:
        return fh.read()


class VersionTests(unittest.TestCase):
    def test_semver_order(self):
        self.assertLess(common.semver_cmp("4.7.9", "4.7.10"), 0)
        self.assertLess(common.semver_cmp("1.0.0-rc.1", "1.0.0"), 0)
        self.assertEqual(common.semver_cmp("1.2.3", "v1.2.3"), 0)

    def test_bump_kind(self):
        self.assertEqual(common.bump_kind("4.7.9", "4.7.10"), "patch")
        self.assertEqual(common.bump_kind("4.7.9", "4.8.0"), "minor")
        self.assertEqual(common.bump_kind("4.7.9", "5.0.0"), "major")

    def test_satisfies(self):
        self.assertTrue(common.satisfies("4.7.10", "^4.7.0"))
        self.assertFalse(common.satisfies("4.7.10", "4.7.7"))
        self.assertTrue(common.satisfies("4.7.10", "~4.7.2"))
        self.assertFalse(common.satisfies("5.0.0", "^4.7.0"))
        self.assertTrue(common.satisfies("1.5.0", ">=1.2.0 <2.0.0"))
        self.assertTrue(common.satisfies("3.0.0", "^1 || ^3"))
        self.assertTrue(common.satisfies("4.1.0", "4.x"))
        self.assertTrue(common.satisfies("0.2.5", "^0.2.3"))
        self.assertFalse(common.satisfies("0.3.0", "^0.2.3"))
        self.assertIsNone(common.satisfies("1.0.0", "git+https://x"))

    def test_maven_order(self):
        self.assertLess(common.maven_cmp("2.0-rc1", "2.0"), 0)
        self.assertLess(common.maven_cmp("2.9", "2.10"), 0)
        self.assertLess(common.maven_cmp("1.33", "2.0"), 0)
        self.assertEqual(common.maven_cmp("1.0", "1.0.0"), 0)
        self.assertLess(common.maven_cmp("2.0.0-beta1", "2.0.0-rc1"), 0)
        self.assertFalse(common.maven_is_stable("3.0.0-M1"))
        self.assertTrue(common.maven_is_stable("3.0.0"))

    def test_cvss(self):
        self.assertEqual(common.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(common.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertIsNone(common.cvss3_score("CVSS:4.0/AV:N"))


class ParseTests(unittest.TestCase):
    def test_pasted_gitlab_text(self):
        text = fixture()
        fmt, found = parse_findings.parse(text)
        self.assertEqual(fmt, "text")
        f = found[0]
        self.assertEqual((f["package"], f["version"], f["ecosystem"]), ("handlebars", "4.7.9", "npm"))
        self.assertEqual(f["fixed_hint"], "4.7.10")
        self.assertEqual(f["cvss"], 9.8)
        self.assertAlmostEqual(f["epss"], 0.01)
        self.assertIs(f["kev"], False)
        # the CVE named in the title is a *different* advisory
        self.assertEqual(f["cves"], ["CVE-2026-106446"])
        self.assertEqual(f["ghsas"], ["GHSA-8r5x-fm3f-whwj"])

    def test_multiple_pasted_findings(self):
        one = fixture()
        _, found = parse_findings.parse(one + "\n" + one.replace("handlebars:4.7.9", "org.yaml:snakeyaml:1.33")
                                        .replace("package-lock.json", "pom.xml"))
        self.assertEqual(len(found), 2)
        self.assertEqual((found[1]["package"], found[1]["ecosystem"]), ("org.yaml:snakeyaml", "maven"))

    def test_gitlab_report_json(self):
        report = {"vulnerabilities": [{
            "id": "x", "name": "lodash prototype pollution", "severity": "High", "solution": "Upgrade to version 4.17.21 or above.",
            "location": {"file": "package-lock.json", "dependency": {"package": {"name": "lodash"}, "version": "4.17.20"}},
            "identifiers": [{"type": "cve", "value": "CVE-2021-23337"}, {"type": "cwe", "value": "77"}]}]}
        fmt, found = parse_findings.parse(json.dumps(report))
        self.assertEqual(fmt, "gitlab-report")
        self.assertEqual(found[0]["fixed_hint"], "4.17.21")
        self.assertEqual(found[0]["cwes"], ["CWE-77"])

    def test_dependabot_json(self):
        alert = [{"number": 7, "dependency": {"manifest_path": "srv/pom.xml"},
                  "security_advisory": {"ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": "CVE-2024-1", "summary": "s",
                                        "severity": "critical", "cvss": {"score": 9.1}},
                  "security_vulnerability": {"package": {"ecosystem": "maven", "name": "org.x:y"},
                                             "first_patched_version": {"identifier": "1.2.3"}}}]
        fmt, found = parse_findings.parse(json.dumps(alert))
        self.assertEqual((fmt, found[0]["ecosystem"], found[0]["fixed_hint"]), ("github-dependabot", "maven", "1.2.3"))

    def test_npm_audit_json(self):
        audit = {"vulnerabilities": {"minimist": {"fixAvailable": {"name": "x", "version": "1.2.6", "isSemVerMajor": False},
                                                  "via": [{"name": "minimist", "title": "pp", "severity": "critical",
                                                           "url": "https://github.com/advisories/GHSA-xvch-5gv4-984h", "range": "<1.2.6"}]}}}
        fmt, found = parse_findings.parse(json.dumps(audit))
        self.assertEqual(fmt, "npm-audit")
        self.assertEqual(found[0]["ghsas"], ["GHSA-xvch-5gv4-984h"])


class TraceTests(unittest.TestCase):
    def test_maven_tree(self):
        tree = ("[INFO] com.acme:srv:jar:1.0.0\n"
                "[INFO] +- a:b:jar:1.0:compile\n"
                "[INFO] |  \\- org.yaml:snakeyaml:jar:2.2:compile\n"
                "[INFO] \\- org.yaml:snakeyaml:jar:1.33:test\n")
        nodes = [n for n in trace_dependency.parse_maven_tree(tree) if n["artifact"] == "snakeyaml"]
        self.assertEqual([(n["version"], n["depth"], n["scope"]) for n in nodes], [("2.2", 2, "compile"), ("1.33", 1, "test")])
        self.assertEqual(nodes[0]["path"][1], "a:b:1.0")


class RiskTests(unittest.TestCase):
    def test_priority(self):
        self.assertEqual(prioritize(5.0, 0.01, True, "Medium")[0], "P0")
        self.assertEqual(prioritize(9.8, 0.008, False, "Critical")[0], "P2")
        self.assertEqual(prioritize(9.8, 0.15, False, "Critical")[0], "P1")
        self.assertEqual(prioritize(3.1, 0.001, False, "Low")[0], "P3")


class HookTests(unittest.TestCase):
    def run_hook(self, script, event):
        p = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "hooks", script)],
                           input=json.dumps(event), capture_output=True, text=True)
        self.assertEqual(p.returncode, 0)
        return json.loads(p.stdout)["hookSpecificOutput"] if p.stdout.strip() else None

    def test_guard(self):
        bash = lambda c: {"tool_name": "Bash", "tool_input": {"command": c}}  # noqa: E731
        self.assertEqual(self.run_hook("guard_remote_actions.py", bash("git push origin x"))["permissionDecision"], "ask")
        self.assertEqual(self.run_hook("guard_remote_actions.py", bash("git push -f origin x"))["permissionDecision"], "deny")
        self.assertEqual(self.run_hook("guard_remote_actions.py", bash("glab mr create --fill"))["permissionDecision"], "ask")
        self.assertIsNone(self.run_hook("guard_remote_actions.py", bash("git diff && npm ls handlebars")))
        self.assertEqual(self.run_hook("guard_remote_actions.py",
                                       {"tool_name": "mcp__x_GitLab__create_merge_request"})["permissionDecision"], "ask")
        self.assertIsNone(self.run_hook("guard_remote_actions.py", {"tool_name": "mcp__x_GitLab__list_vulnerabilities"}))

    def test_post_edit(self):
        out = self.run_hook("post_manifest_edit.py", {"tool_input": {"file_path": "/a/pom.xml"}})
        self.assertIn("verify.py", out["additionalContext"])
        self.assertIsNone(self.run_hook("post_manifest_edit.py", {"tool_input": {"file_path": "/a/readme.md"}}))


if __name__ == "__main__":
    unittest.main()
