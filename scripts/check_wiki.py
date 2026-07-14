#!/usr/bin/env python3
"""Validate the repository-owned GitHub wiki source."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parents[1]
WIKI = ROOT / "docs" / "wiki"
REPOSITORY = "georgestarcher/dmarcgo"

PAGES = (
    "API-Schemas-Standards-and-Versioning.md",
    "Approved-Campaign-Classification.md",
    "Automation-Outputs-and-AI-Safety.md",
    "DMARC-Report-Ingestion-and-Reporting.md",
    "DNS-and-Report-Correlation.md",
    "Defensive-Exports.md",
    "Domain-Portfolio-and-DNS-Monitoring.md",
    "Home.md",
    "Scoring-Confidence-and-Maturity.md",
    "Suspicious-Source-and-Phishing-Review.md",
    "Wiki-Maintenance.md",
    "_Footer.md",
    "_Sidebar.md",
)

JOURNEY_PAGES = tuple(
    page
    for page in PAGES
    if page not in {"Home.md", "Wiki-Maintenance.md", "_Footer.md", "_Sidebar.md"}
)

REQUIRED_HEADINGS = (
    "## Who this is for",
    "## Question this workflow answers",
    "## Inputs",
    "## Activity and side effects",
    "## Starting APIs",
    "## Outputs",
    "## What this does not prove",
    "## Sensitive data",
    "## Safe next steps",
    "## Authoritative references",
)

SOURCE_NOTICE = "Navigation guide, not a versioned contract."
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
FILE_RE = re.compile(r"(?:[A-Z]|_[A-Z])[A-Za-z0-9]*(?:-[A-Za-z0-9]+)*\.md")
SECRET_RE = re.compile(
    r"(?:-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----|"
    r"github_pat_[A-Za-z0-9_]{8,}|ghp_[A-Za-z0-9]{8,}|"
    r"AKIA[0-9A-Z]{16})"
)
PRIVATE_MARKERS = (
    "/Users/",
    ".codex-tmp",
    "test_dmarc_reports",
    "private-test-domains",
    "private_test_domains",
)


def error(errors: list[str], page: str, message: str) -> None:
    errors.append(f"{page}: {message}")


def repository_path(target: str) -> str | None:
    parsed = urlparse(target)
    prefix = f"/{REPOSITORY}/"
    if parsed.netloc != "github.com" or not parsed.path.startswith(prefix):
        return None

    remainder = parsed.path[len(prefix) :]
    for marker in ("blob/main/", "tree/main/"):
        if remainder.startswith(marker):
            return unquote(remainder[len(marker) :])
    return None


def exact_path_exists(relative: str) -> bool:
    current = ROOT
    for part in Path(relative).parts:
        if part in {"", ".", ".."} or not current.is_dir():
            return False
        names = {entry.name for entry in current.iterdir()}
        if part not in names:
            return False
        current /= part
    return current.exists()


def wiki_target(target: str) -> str | None:
    if target.startswith(("https://", "http://", "mailto:", "#")):
        return None
    plain = unquote(target.split("#", 1)[0]).strip()
    if not plain:
        return None
    return plain if plain.endswith(".md") else f"{plain}.md"


def main() -> int:
    errors: list[str] = []
    expected = set(PAGES)

    if not WIKI.is_dir():
        print(f"wiki source directory is missing: {WIKI}", file=sys.stderr)
        return 1

    actual = {path.name for path in WIKI.glob("*.md")}
    for name in sorted(expected - actual):
        error(errors, name, "required page is missing")
    for name in sorted(actual - expected):
        error(errors, name, "page is not registered in check_wiki.py")

    folded: dict[str, str] = {}
    for name in sorted(actual):
        if not FILE_RE.fullmatch(name):
            error(errors, name, "filename must use canonical GitHub-wiki title casing")
        key = name.removesuffix(".md").casefold()
        if previous := folded.get(key):
            error(errors, name, f"slug collides with {previous}")
        folded[key] = name

    contents: dict[str, str] = {}
    for name in sorted(actual):
        path = WIKI / name
        if path.is_symlink() or not path.is_file():
            error(errors, name, "page must be a regular file, not a symlink")
            continue
        text = path.read_text(encoding="utf-8")
        contents[name] = text
        if SECRET_RE.search(text):
            error(errors, name, "contains a credential or private-key marker")
        for marker in PRIVATE_MARKERS:
            if marker.casefold() in text.casefold():
                error(errors, name, f"contains prohibited private marker {marker!r}")

        if name not in {"_Footer.md", "_Sidebar.md"} and SOURCE_NOTICE not in text:
            error(errors, name, "source-of-truth notice is missing")

        if name in JOURNEY_PAGES:
            for heading in REQUIRED_HEADINGS:
                if heading not in text:
                    error(errors, name, f"required heading is missing: {heading}")

        for target in LINK_RE.findall(text):
            target = target.strip().split(maxsplit=1)[0].strip("<>")
            if internal := wiki_target(target):
                if internal not in actual:
                    error(errors, name, f"wiki link does not match an exact page: {target}")
            if relative := repository_path(target):
                if not exact_path_exists(relative):
                    error(errors, name, f"repository link does not match an exact path: {relative}")

    for navigation in ("Home.md", "_Sidebar.md"):
        text = contents.get(navigation, "")
        linked = {
            wiki_target(target.strip().split(maxsplit=1)[0].strip("<>"))
            for target in LINK_RE.findall(text)
        }
        for page in sorted(expected - {"_Footer.md", "_Sidebar.md"}):
            if page not in linked and page != navigation:
                error(errors, navigation, f"does not link to {page}")

    if errors:
        print("wiki validation failed:", file=sys.stderr)
        for message in sorted(errors):
            print(f"- {message}", file=sys.stderr)
        return 1

    print(f"wiki validation passed: {len(actual)} canonical pages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
