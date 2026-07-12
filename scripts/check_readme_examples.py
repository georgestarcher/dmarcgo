#!/usr/bin/env python3
"""Compile Go code blocks from README.md in an isolated module."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path


def main() -> int:
    repo = Path.cwd()
    readme = (repo / "README.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```go\n(.*?)\n```", readme, flags=re.DOTALL)

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        (tmpdir / "go.mod").write_text(
            "\n".join(
                [
                    "module readmecheck",
                    "",
                    "go 1.25",
                    "",
                    "require github.com/georgestarcher/dmarcgo/v2 v2.0.0",
                    "",
                    f"replace github.com/georgestarcher/dmarcgo/v2 => {repo}",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        for index, block in enumerate(blocks, start=1):
            block_dir = tmpdir / f"block{index}"
            block_dir.mkdir()
            (block_dir / "main.go").write_text(block, encoding="utf-8")

            result = subprocess.run(
                ["go", "build", "-mod=mod", "."],
                cwd=block_dir,
                env=os.environ.copy(),
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                print(f"README Go block {index} failed to compile")
                print(result.stdout)
                print(result.stderr)
                return result.returncode

    print(f"compiled {len(blocks)} README Go block(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
