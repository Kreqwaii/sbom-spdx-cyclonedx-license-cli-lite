import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import sbom_audit

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


class TestSBOMParser(unittest.TestCase):
    def test_parse_cyclonedx_clean(self):
        data = json.loads((SAMPLES_DIR / "cyclonedx_clean.json").read_text(encoding="utf-8"))
        fmt, spec, comps = sbom_audit.parse_sbom(data)
        self.assertEqual(fmt, "CycloneDX")
        self.assertEqual(spec, "1.5")
        self.assertEqual(len(comps), 2)
        self.assertEqual(comps[0].name, "requests")
        self.assertEqual(comps[0].licenses, ["Apache-2.0"])
        self.assertIn("SHA-256", comps[0].hashes)

    def test_parse_cyclonedx_14_expression_and_author(self):
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "name": "foo",
                    "version": "1.0.0",
                    "author": "Alice",
                    "licenses": [{"expression": "MIT OR Apache-2.0"}],
                }
            ],
        }
        fmt, spec, comps = sbom_audit.parse_sbom(data)
        self.assertEqual(fmt, "CycloneDX")
        self.assertEqual(spec, "1.4")
        self.assertEqual(comps[0].licenses, ["MIT OR Apache-2.0"])
        self.assertEqual(comps[0].supplier, "Alice")

    def test_parse_spdx_sample(self):
        data = json.loads((SAMPLES_DIR / "spdx_sample.json").read_text(encoding="utf-8"))
        fmt, spec, comps = sbom_audit.parse_sbom(data)
        self.assertEqual(fmt, "SPDX")
        self.assertEqual(spec, "SPDX-2.3")
        self.assertEqual(len(comps), 2)
        self.assertEqual(comps[0].purl, "pkg:pypi/urllib3@2.2.1")
        self.assertEqual(comps[1].supplier, "")  # NOASSERTION normalized to empty

    def test_parse_invalid_root_raises(self):
        with self.assertRaises(ValueError):
            sbom_audit.parse_sbom(["not", "a", "dict"])  # type: ignore[arg-type]

    def test_parse_unknown_format_raises(self):
        with self.assertRaises(ValueError):
            sbom_audit.parse_sbom({"hello": "world"})


class TestAuditRules(unittest.TestCase):
    def test_clean_cyclonedx_zero_findings(self):
        data = json.loads((SAMPLES_DIR / "cyclonedx_clean.json").read_text(encoding="utf-8"))
        fmt, spec, comps = sbom_audit.parse_sbom(data)
        report = sbom_audit.audit_components(fmt, spec, comps)
        self.assertEqual(len(report.findings), 0)

    def test_copyleft_agpl_detected(self):
        comps = [sbom_audit.Component(name="a", version="1.0.0", purl="pkg:pypi/a@1.0.0", licenses=["AGPL-3.0-only"], hashes={"SHA-256": "abc"}, supplier="Org")]
        report = sbom_audit.audit_components("CycloneDX", "1.5", comps)
        self.assertEqual([f.rule_id for f in report.findings], ["LIC-COPYLEFT"])
        self.assertEqual(report.findings[0].severity, "critical")

    def test_copyleft_gpl3_detected(self):
        comps = [sbom_audit.Component(name="a", version="1.0.0", purl="pkg:pypi/a@1.0.0", licenses=["GPL-3.0-or-later"], hashes={"SHA-256": "abc"}, supplier="Org")]
        report = sbom_audit.audit_components("CycloneDX", "1.5", comps)
        self.assertIn("LIC-COPYLEFT", [f.rule_id for f in report.findings])

    def test_copyleft_sspl_detected(self):
        comps = [sbom_audit.Component(name="db", version="1.0.0", purl="pkg:pypi/db@1.0.0", licenses=["SSPL-1.0"], hashes={"SHA-256": "abc"}, supplier="Org")]
        report = sbom_audit.audit_components("SPDX", "SPDX-2.3", comps)
        self.assertIn("LIC-COPYLEFT", [f.rule_id for f in report.findings])

    def test_missing_license_detected(self):
        comps = [sbom_audit.Component(name="a", version="1.0.0", purl="pkg:pypi/a@1.0.0", licenses=[], hashes={"SHA-256": "abc"}, supplier="Org")]
        report = sbom_audit.audit_components("CycloneDX", "1.5", comps)
        self.assertEqual([f.rule_id for f in report.findings], ["LIC-MISSING"])

    def test_unknown_license_detected(self):
        for marker in ("UNKNOWN", "NOASSERTION", "NONE", "UNLICENSED"):
            comps = [sbom_audit.Component(name="a", version="1.0.0", purl="pkg:pypi/a@1.0.0", licenses=[marker], hashes={"SHA-256": "abc"}, supplier="Org")]
            report = sbom_audit.audit_components("CycloneDX", "1.5", comps)
            self.assertIn("LIC-UNKNOWN", [f.rule_id for f in report.findings])

    def test_custom_denied_license(self):
        comps = [sbom_audit.Component(name="a", version="1.0.0", purl="pkg:pypi/a@1.0.0", licenses=["EPL-2.0"], hashes={"SHA-256": "abc"}, supplier="Org")]
        report = sbom_audit.audit_components("CycloneDX", "1.5", comps, denied_licenses=["EPL-2.0"])
        self.assertIn("LIC-COPYLEFT", [f.rule_id for f in report.findings])

    def test_floating_versions_detected(self):
        for ver in ("", "*", "latest", "^1.2.3", "~2.0", ">=1.0.0", "1.2.x", "main"):
            comps = [sbom_audit.Component(name="a", version=ver, purl="pkg:pypi/a", licenses=["MIT"], hashes={"SHA-256": "abc"}, supplier="Org")]
            report = sbom_audit.audit_components("CycloneDX", "1.5", comps)
            self.assertIn("VER-UNPINNED", [f.rule_id for f in report.findings], f"Failed for version={ver!r}")

    def test_pinned_version_passes(self):
        comps = [sbom_audit.Component(name="a", version="1.2.3", purl="pkg:pypi/a@1.2.3", licenses=["MIT"], hashes={"SHA-256": "abc"}, supplier="Org")]
        report = sbom_audit.audit_components("CycloneDX", "1.5", comps)
        self.assertEqual(report.findings, [])

    def test_missing_sha256_detected(self):
        comps = [sbom_audit.Component(name="a", version="1.0.0", purl="pkg:pypi/a@1.0.0", licenses=["MIT"], hashes={"MD5": "123"}, supplier="Org")]
        report = sbom_audit.audit_components("CycloneDX", "1.5", comps)
        self.assertEqual([f.rule_id for f in report.findings], ["HASH-MISSING-SHA256"])

    def test_missing_purl_detected(self):
        comps = [sbom_audit.Component(name="a", version="1.0.0", purl="", licenses=["MIT"], hashes={"SHA-256": "abc"}, supplier="Org")]
        report = sbom_audit.audit_components("CycloneDX", "1.5", comps)
        self.assertEqual([f.rule_id for f in report.findings], ["PURL-MISSING"])

    def test_missing_supplier_detected(self):
        comps = [sbom_audit.Component(name="a", version="1.0.0", purl="pkg:pypi/a@1.0.0", licenses=["MIT"], hashes={"SHA-256": "abc"}, supplier="")]
        report = sbom_audit.audit_components("CycloneDX", "1.5", comps)
        self.assertEqual([f.rule_id for f in report.findings], ["META-NO-SUPPLIER"])

    def test_duplicate_conflicting_versions_detected(self):
        comps = [
            sbom_audit.Component(name="requests", version="2.31.0", purl="pkg:pypi/requests@2.31.0", licenses=["Apache-2.0"], hashes={"SHA-256": "a"}, supplier="PSF"),
            sbom_audit.Component(name="requests", version="2.28.2", purl="pkg:pypi/requests@2.28.2", licenses=["Apache-2.0"], hashes={"SHA-256": "b"}, supplier="PSF"),
        ]
        report = sbom_audit.audit_components("CycloneDX", "1.5", comps)
        self.assertIn("DUP-CONFLICT-VER", [f.rule_id for f in report.findings])


class TestDiffAndFormatting(unittest.TestCase):
    def test_diff_added_removed_changed(self):
        old = [
            sbom_audit.Component(name="a", version="1.0.0", licenses=["MIT"]),
            sbom_audit.Component(name="b", version="2.0.0", licenses=["Apache-2.0"]),
        ]
        new = [
            sbom_audit.Component(name="b", version="2.1.0", licenses=["Apache-2.0"]),
            sbom_audit.Component(name="c", version="0.1.0", licenses=["BSD-3-Clause"]),
        ]
        res = sbom_audit.diff_sboms(old, new)
        self.assertEqual(res["added_count"], 1)
        self.assertEqual(res["removed_count"], 1)
        self.assertEqual(res["changed_count"], 1)
        self.assertEqual(res["added"][0]["name"], "c")
        self.assertEqual(res["removed"][0]["name"], "a")
        self.assertEqual(res["changed"][0]["new_version"], "2.1.0")

    def test_format_json_valid(self):
        report = sbom_audit.audit_components("CycloneDX", "1.5", [])
        parsed = json.loads(sbom_audit.format_report_json(report))
        self.assertEqual(parsed["sbom_format"], "CycloneDX")
        self.assertEqual(parsed["total_components"], 0)

    def test_format_markdown_clean(self):
        report = sbom_audit.audit_components("CycloneDX", "1.5", [])
        md = sbom_audit.format_report_markdown(report)
        self.assertIn("All checks passed", md)

    def test_format_markdown_with_findings(self):
        comps = [sbom_audit.Component(name="x", version="1.0.0")]
        report = sbom_audit.audit_components("CycloneDX", "1.5", comps)
        md = sbom_audit.format_report_markdown(report)
        self.assertIn("| Severity | Rule |", md)
        self.assertIn("LIC-MISSING", md)

    def test_should_fail_thresholds(self):
        findings = [sbom_audit.Finding(rule_id="META-NO-SUPPLIER", severity="low", component="x", version="1.0", message="m")]
        self.assertFalse(sbom_audit.should_fail(findings, "none"))
        self.assertFalse(sbom_audit.should_fail(findings, "medium"))
        self.assertTrue(sbom_audit.should_fail(findings, "low"))


class TestCLI(unittest.TestCase):
    def test_cli_audit_clean_exit_0(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = sbom_audit.main(["audit", str(SAMPLES_DIR / "cyclonedx_clean.json"), "--fail-on", "low"])
        self.assertEqual(code, 0)

    def test_cli_audit_risky_exit_1(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = sbom_audit.main(["audit", str(SAMPLES_DIR / "cyclonedx_risky.json"), "--fail-on", "critical"])
        self.assertEqual(code, 1)

    def test_cli_audit_spdx_json_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = sbom_audit.main(["audit", str(SAMPLES_DIR / "spdx_sample.json"), "--format", "json", "--fail-on", "none"])
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["sbom_format"], "SPDX")

    def test_cli_diff_markdown_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = sbom_audit.main(["diff", str(SAMPLES_DIR / "cyclonedx_clean.json"), str(SAMPLES_DIR / "cyclonedx_risky.json")])
        self.assertEqual(code, 0)
        self.assertIn("# SBOM Diff Report", buf.getvalue())

    def test_cli_missing_file_exit_2(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code = sbom_audit.main(["audit", str(SAMPLES_DIR / "does_not_exist.json")])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
