#!/usr/bin/env python3
"""Offline regression tests for public release verification."""

from __future__ import annotations

import json
import unittest

import verify_release_publication


class ReleasePublicationTests(unittest.TestCase):
    def valid_responses(self, tag: str = "v3.0.1") -> dict[str, bytes]:
        return {
            "github_release": json.dumps(
                {
                    "tag_name": tag,
                    "draft": False,
                    "prerelease": "-" in tag,
                }
            ).encode(),
            "go_proxy_info": json.dumps(
                {"Version": tag, "Time": "2026-07-16T14:00:00Z"}
            ).encode(),
            "go_proxy_mod": (
                "module github.com/georgestarcher/dmarcgo/v3\n\ngo 1.25.0\n"
            ).encode(),
            "checksum_database": (
                f"github.com/georgestarcher/dmarcgo/v3 {tag} h1:module\n"
                f"github.com/georgestarcher/dmarcgo/v3 {tag}/go.mod h1:mod\n"
            ).encode(),
            "package_documentation": (
                f"<html>github.com/georgestarcher/dmarcgo/v3 {tag}</html>"
            ).encode(),
        }

    def test_accepts_complete_publication(self) -> None:
        self.assertEqual(
            verify_release_publication.validate_publication_responses(
                "v3.0.1", self.valid_responses()
            ),
            [],
        )

    def test_accepts_matching_prerelease(self) -> None:
        tag = "v3.1.0-rc.1"
        self.assertEqual(
            verify_release_publication.validate_publication_responses(
                tag, self.valid_responses(tag)
            ),
            [],
        )

    def test_rejects_wrong_release_and_proxy_versions(self) -> None:
        responses = self.valid_responses()
        responses["github_release"] = json.dumps(
            {"tag_name": "v3.0.0", "draft": True, "prerelease": False}
        ).encode()
        responses["go_proxy_info"] = json.dumps({"Version": "v3.0.0"}).encode()
        errors = verify_release_publication.validate_publication_responses(
            "v3.0.1", responses
        )
        self.assertTrue(any("tag_name" in error for error in errors))
        self.assertTrue(any("still a draft" in error for error in errors))
        self.assertTrue(any("Version" in error for error in errors))

    def test_rejects_missing_checksums_and_documentation_identity(self) -> None:
        responses = self.valid_responses()
        responses["checksum_database"] = b"unrelated checksum response\n"
        responses["package_documentation"] = b"<html>not indexed</html>"
        errors = verify_release_publication.validate_publication_responses(
            "v3.0.1", responses
        )
        self.assertTrue(any("module checksum is missing" in error for error in errors))
        self.assertTrue(any("go.mod checksum is missing" in error for error in errors))
        self.assertTrue(any("module path is missing" in error for error in errors))
        self.assertTrue(any("version is missing" in error for error in errors))

    def test_rejects_invalid_tag_without_interpreting_responses(self) -> None:
        self.assertEqual(
            verify_release_publication.validate_publication_responses("main", {}),
            ["release tag must be a semantic v3 version, got main"],
        )


if __name__ == "__main__":
    unittest.main()
