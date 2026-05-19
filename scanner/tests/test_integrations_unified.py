"""Tests for unified tool layer."""

import unittest

from scanner.integrations import get_tool_definitions, validate_after_patch
from scanner.integrations.schema import TOOL_SCHEMA_VERSION


class TestUnifiedTools(unittest.TestCase):
    def test_tool_definitions_version(self) -> None:
        tools = get_tool_definitions()
        self.assertGreaterEqual(len(tools), 3)
        names = {t["name"] for t in tools}
        self.assertIn("scan_project", names)
        self.assertIn("scan_full", names)
        self.assertEqual(TOOL_SCHEMA_VERSION, "1.0.0")

    def test_validate_after_patch_diff(self) -> None:
        baseline = {
            "affected_components": [
                {"name": "lodash", "version": "4.17.15", "vulnerabilities": 2},
            ]
        }
        after = {
            "affected_components": [
                {"name": "lodash", "version": "4.17.21", "vulnerabilities": 0},
            ]
        }
        result = validate_after_patch(baseline, after)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["resolved_count"], 1)
        self.assertEqual(result["new_count"], 1)


if __name__ == "__main__":
    unittest.main()
