#!/usr/bin/env python3
"""Validate dmarcgo v3 tag, module-path, and changelog metadata."""

from __future__ import annotations

import argparse
import datetime
import re
import sys
from pathlib import Path


MODULE_PATH = "github.com/georgestarcher/dmarcgo/v3"
SEMVER_NUMBER = r"(?:0|[1-9][0-9]*)"
SEMVER_PRERELEASE_IDENTIFIER = (
    r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
)
SEMVER_BUILD_IDENTIFIER = r"[0-9A-Za-z-]+"
TAG_PATTERN = re.compile(
    rf"^v3\.{SEMVER_NUMBER}\.{SEMVER_NUMBER}"
    rf"(?:-{SEMVER_PRERELEASE_IDENTIFIER}(?:\.{SEMVER_PRERELEASE_IDENTIFIER})*)?"
    rf"(?:\+{SEMVER_BUILD_IDENTIFIER}(?:\.{SEMVER_BUILD_IDENTIFIER})*)?$"
)
RELEASE_HEADING_PATTERN = re.compile(
    r"^## \[([^]]+)\] - \d{4}-\d{2}-\d{2}$"
)


def newest_release_tag(changelog: str) -> str | None:
    """Return the first dated changelog version as a v-prefixed tag."""
    version = next(
        (
            match.group(1)
            for line in changelog.splitlines()
            if (match := RELEASE_HEADING_PATTERN.fullmatch(line))
        ),
        None,
    )
    return None if version is None else f"v{version}"


def validate_release_metadata(tag: str, go_mod: str, changelog: str) -> list[str]:
    """Return deterministic validation errors for supplied release metadata."""

    errors: list[str] = []
    if not TAG_PATTERN.fullmatch(tag):
        errors.append(f"release tag must be a semantic v3 version, got {tag}")

    module_line = next(
        (line.strip() for line in go_mod.splitlines() if line.startswith("module ")),
        "",
    )
    expected_module_line = f"module {MODULE_PATH}"
    if module_line != expected_module_line:
        errors.append(
            f"module path must be {MODULE_PATH}, got {module_line.removeprefix('module ') or '<missing>'}"
        )

    version = tag.removeprefix("v")
    heading = re.compile(
        rf"^## \[{re.escape(version)}\] - (?P<date>\d{{4}}-\d{{2}}-\d{{2}})$"
    )
    heading_match = next(
        (match for line in changelog.splitlines() if (match := heading.fullmatch(line))),
        None,
    )
    if heading_match is None:
        errors.append(f"dated changelog entry is missing for {version}")
    else:
        try:
            datetime.date.fromisoformat(heading_match.group("date"))
        except ValueError:
            errors.append(f"changelog date is invalid for {version}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tag",
        help="release tag including leading v; defaults to the newest dated changelog entry",
    )
    parser.add_argument("--go-mod", default="go.mod", help="go.mod path")
    parser.add_argument("--changelog", default="CHANGELOG.md", help="changelog path")
    args = parser.parse_args()

    go_mod = Path(args.go_mod).read_text(encoding="utf-8")
    changelog = Path(args.changelog).read_text(encoding="utf-8")
    tag = args.tag or newest_release_tag(changelog)
    if tag is None:
        print("no dated changelog release exists", file=sys.stderr)
        return 1

    errors = validate_release_metadata(tag, go_mod, changelog)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
