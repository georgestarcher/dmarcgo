#!/usr/bin/env python3
"""Regression tests for v3 release metadata validation."""

from __future__ import annotations

import unittest

import validate_release_metadata


class ReleaseMetadataTests(unittest.TestCase):
    def test_accepts_v3_tag_module_and_dated_changelog(self) -> None:
        errors = validate_release_metadata.validate_release_metadata(
            "v3.0.0",
            "module github.com/georgestarcher/dmarcgo/v3\n\ngo 1.25.0\n",
            "# Changelog\n\n## [3.0.0] - 2026-07-16\n\nRelease notes.\n",
        )
        self.assertEqual(errors, [])

    def test_rejects_wrong_major_tag(self) -> None:
        errors = validate_release_metadata.validate_release_metadata(
            "v2.2.0",
            "module github.com/georgestarcher/dmarcgo/v3\n",
            "## [2.2.0] - 2026-07-16\n",
        )
        self.assertTrue(any("semantic v3 version" in error for error in errors))

    def test_rejects_non_semantic_v3_tags(self) -> None:
        for tag in ("v3.01.0", "v3.0.0-", "v3.0.0-alpha..1", "v3.0.0+build..1"):
            with self.subTest(tag=tag):
                errors = validate_release_metadata.validate_release_metadata(
                    tag,
                    "module github.com/georgestarcher/dmarcgo/v3\n",
                    f"## [{tag.removeprefix('v')}] - 2026-07-16\n",
                )
                self.assertTrue(
                    any("semantic v3 version" in error for error in errors),
                    errors,
                )

    def test_rejects_wrong_module_path(self) -> None:
        errors = validate_release_metadata.validate_release_metadata(
            "v3.0.0",
            "module github.com/georgestarcher/dmarcgo/v2\n",
            "## [3.0.0] - 2026-07-16\n",
        )
        self.assertTrue(any("module path must be" in error for error in errors))

    def test_rejects_missing_dated_changelog_entry(self) -> None:
        errors = validate_release_metadata.validate_release_metadata(
            "v3.0.0",
            "module github.com/georgestarcher/dmarcgo/v3\n",
            "## Unreleased\n",
        )
        self.assertTrue(any("dated changelog entry" in error for error in errors))

    def test_rejects_invalid_changelog_date(self) -> None:
        errors = validate_release_metadata.validate_release_metadata(
            "v3.0.0",
            "module github.com/georgestarcher/dmarcgo/v3\n",
            "## [3.0.0] - 2026-02-30\n",
        )
        self.assertTrue(any("changelog date is invalid" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
