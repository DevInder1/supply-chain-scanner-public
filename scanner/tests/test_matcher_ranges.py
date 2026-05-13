"""Regression tests for OSV-style affected range evaluation."""

from __future__ import annotations

import unittest

from scanner.core.matcher import evaluate_range_events


class TestEvaluateRangeEvents(unittest.TestCase):
    def test_not_affected_after_fixed_boundary(self) -> None:
        events = [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
        self.assertFalse(evaluate_range_events("3.0.0", events))

    def test_affected_between_introduced_and_fixed(self) -> None:
        events = [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
        self.assertTrue(evaluate_range_events("1.5.0", events))

    def test_not_affected_on_fixed_version(self) -> None:
        events = [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
        self.assertFalse(evaluate_range_events("2.0.0", events))

    def test_last_affected_inclusive(self) -> None:
        events = [{"introduced": "0"}, {"last_affected": "1.2.3"}]
        self.assertTrue(evaluate_range_events("1.2.3", events))
        self.assertFalse(evaluate_range_events("1.2.4", events))


if __name__ == "__main__":
    unittest.main()
