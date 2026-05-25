"""Regression tests for OSV-style affected range evaluation."""

from __future__ import annotations

import unittest

from scanner.core.matcher import (
    evaluate_range_events,
    is_range_constraint,
    version_matches,
)


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


class TestIsRangeConstraint(unittest.TestCase):
    """Detect unresolved range expressions vs pinned versions."""

    def test_pinned_versions_are_not_ranges(self) -> None:
        for v in ["1.2.3", "2.31.0", "0.0.1", "10.20.30", "1.2.3-rc1", "1.2.3+build5"]:
            self.assertFalse(is_range_constraint(v), f"{v!r} should be pinned")

    def test_caret_npm_range(self) -> None:
        self.assertTrue(is_range_constraint("^4.17.0"))

    def test_tilde_npm_range(self) -> None:
        self.assertTrue(is_range_constraint("~4.17.0"))

    def test_pypi_compatible_release(self) -> None:
        self.assertTrue(is_range_constraint("~=2.31.0"))

    def test_greater_or_equal(self) -> None:
        self.assertTrue(is_range_constraint(">=2.31.0"))

    def test_strict_greater(self) -> None:
        self.assertTrue(is_range_constraint(">2.31.0"))

    def test_less_or_equal(self) -> None:
        self.assertTrue(is_range_constraint("<=2.31.0"))

    def test_strict_less(self) -> None:
        self.assertTrue(is_range_constraint("<2.31.0"))

    def test_not_equal(self) -> None:
        self.assertTrue(is_range_constraint("!=2.31.0"))

    def test_wildcard(self) -> None:
        self.assertTrue(is_range_constraint("*"))

    def test_empty_string_is_not_range(self) -> None:
        self.assertFalse(is_range_constraint(""))

    def test_none_safe(self) -> None:
        self.assertFalse(is_range_constraint(None))  # type: ignore[arg-type]

    def test_whitespace_prefix_does_not_break(self) -> None:
        self.assertTrue(is_range_constraint("  >=2.31.0"))

    def test_double_equals_is_pinned(self) -> None:
        # "==2.31.0" is a PyPI-style pinned spec — the version is exact.
        # Today we conservatively still treat double-equals strings as
        # pinned (the existing regex strips the prefix in normalize_version).
        # Document the current behaviour so future changes are deliberate.
        self.assertFalse(is_range_constraint("==2.31.0"))


class TestVersionMatchesSkipRanges(unittest.TestCase):
    """version_matches() must NOT flag advisories for unresolved range strings."""

    AFFECTED_ENTRY = {
        "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "2.31.0"}, {"fixed": "2.32.0"}]}
        ]
    }

    def test_pinned_version_in_range_still_matches(self) -> None:
        # Regression guard: pinned versions that fall inside the affected range
        # must still match (existing behaviour preserved).
        self.assertTrue(version_matches("2.31.0", self.AFFECTED_ENTRY))

    def test_pinned_version_outside_range_does_not_match(self) -> None:
        self.assertFalse(version_matches("2.32.0", self.AFFECTED_ENTRY))

    def test_range_constraint_is_skipped(self) -> None:
        # The fix: ">=2.31.0" must NOT match. The floor (2.31.0) is not the
        # installed version — the lockfile-resolved pin is.
        self.assertFalse(version_matches(">=2.31.0", self.AFFECTED_ENTRY))

    def test_caret_range_is_skipped(self) -> None:
        self.assertFalse(version_matches("^2.31.0", self.AFFECTED_ENTRY))

    def test_tilde_range_is_skipped(self) -> None:
        self.assertFalse(version_matches("~2.31.0", self.AFFECTED_ENTRY))

    def test_explicit_pinned_in_explicit_versions_list_still_matches(self) -> None:
        # Explicit version lists (no range block) must keep working unchanged.
        self.assertTrue(version_matches("1.0.0", {"versions": ["1.0.0", "1.0.1"]}))

    def test_range_skipped_even_when_explicit_versions_contains_floor(self) -> None:
        # If a manifest gives ">=1.0.0" and the advisory lists ["1.0.0"], we
        # still skip — the installed version isn't necessarily 1.0.0.
        self.assertFalse(version_matches(">=1.0.0", {"versions": ["1.0.0"]}))


if __name__ == "__main__":
    unittest.main()
