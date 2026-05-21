"""Tests for CLI validate mode and report loading."""

import json
import tempfile
import unittest
from pathlib import Path
from scanner.integrations.validate_cli import load_scan_payload
from scanner.main import build_parser, execute_validate


class TestValidateCli(unittest.TestCase):
    def test_load_summary_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.json"
            path.write_text(
                json.dumps(
                    {
                        "affected_components": [
                            {"name": "lodash", "version": "4.17.15", "vulnerabilities": 2}
                        ]
                    }
                ),
                encoding="utf-8",
            )
            payload = load_scan_payload(path)
            self.assertEqual(len(payload["affected_components"]), 1)

    def test_load_full_report_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan-report.json"
            path.write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "component": {"name": "lodash", "version": "4.17.15"},
                                "advisories": [{"id": "CVE-1"}, {"id": "CVE-2"}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            payload = load_scan_payload(path)
            self.assertEqual(payload["affected_components"][0]["vulnerabilities"], 2)

    def test_execute_validate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            baseline = Path(tmp) / "baseline.json"
            after = Path(tmp) / "after.json"
            baseline.write_text(
                json.dumps(
                    {
                        "affected_components": [
                            {"name": "lodash", "version": "4.17.15", "vulnerabilities": 1}
                        ]
                    }
                ),
                encoding="utf-8",
            )
            after.write_text(
                json.dumps({"affected_components": []}),
                encoding="utf-8",
            )
            args = build_parser().parse_args(
                [
                    "--validate",
                    "--baseline-report",
                    str(baseline),
                    "--after-report",
                    str(after),
                ]
            )
            result = execute_validate(args)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["resolved_count"], 1)
            self.assertTrue(result["validation_passed"])

    def test_scan_help_unchanged(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--scan", "project", "--project-path", "."])
        self.assertFalse(args.validate)


if __name__ == "__main__":
    unittest.main()
