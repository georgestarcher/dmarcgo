#!/usr/bin/env python3
"""Fail if Go total coverage is below the configured threshold."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="coverage.out", help="coverage profile path")
    parser.add_argument("--min", type=float, default=75.0, help="minimum total coverage percentage")
    args = parser.parse_args()

    profile = Path(args.profile)
    if not profile.exists():
        print(f"coverage profile not found: {profile}", file=sys.stderr)
        return 2

    result = subprocess.run(
        ["go", "tool", "cover", f"-func={profile}"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return result.returncode

    print(result.stdout, end="")
    total_line = next((line for line in result.stdout.splitlines() if line.startswith("total:")), "")
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)%", total_line)
    if not match:
        print("could not find total coverage", file=sys.stderr)
        return 2

    coverage = float(match.group(1))
    if coverage < args.min:
        print(f"coverage {coverage:.1f}% is below required {args.min:.1f}%", file=sys.stderr)
        return 1

    print(f"coverage {coverage:.1f}% meets required {args.min:.1f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
