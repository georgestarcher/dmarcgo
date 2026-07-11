#!/usr/bin/env python3
"""Print one dated release section from CHANGELOG.md."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "version",
        nargs="?",
        help="semantic version without the leading v; defaults to the newest dated release",
    )
    parser.add_argument("--changelog", default="CHANGELOG.md", help="changelog path")
    args = parser.parse_args()

    lines = Path(args.changelog).read_text(encoding="utf-8").splitlines()
    release_heading = re.compile(r"^## \[([^]]+)\] - \d{4}-\d{2}-\d{2}$")
    version = args.version
    if version is None:
        version = next(
            (match.group(1) for line in lines if (match := release_heading.fullmatch(line))),
            None,
        )
        if version is None:
            print(f"no dated release exists in {args.changelog}", file=sys.stderr)
            return 1

    heading = re.compile(rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$")
    start = next((index + 1 for index, line in enumerate(lines) if heading.fullmatch(line)), None)
    if start is None:
        print(f"release {version} is missing from {args.changelog}", file=sys.stderr)
        return 1

    end = next(
        (index for index in range(start, len(lines)) if lines[index].startswith("## [")),
        len(lines),
    )
    body = "\n".join(lines[start:end]).strip()
    if not body:
        print(f"release {version} has no notes in {args.changelog}", file=sys.stderr)
        return 1

    print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
