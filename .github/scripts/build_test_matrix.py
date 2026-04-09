#!/usr/bin/env python3
"""
Generate the GitHub Actions test matrix for collector tests.

Discovers all collectors with test directories (test/ or tests/) and
includes them in the matrix. All collectors are always tested.
"""

import json
import os
from pathlib import Path

# Directories that are NOT collectors (excluded from discovery)
EXCLUDED_DIRS = {
    ".circleci",
    ".github",
    "scripts",
    ".git",
    "__pycache__",
    "node_modules",
}


def discover_collectors() -> list[str]:
    """Find all collector directories that contain test/ or tests/ subdirectories."""
    collectors = []
    for entry in sorted(Path(".").iterdir()):
        if (
            not entry.is_dir()
            or entry.name.startswith(".")
            or entry.name in EXCLUDED_DIRS
        ):
            continue
        if (entry / "test").is_dir() or (entry / "tests").is_dir():
            collectors.append(entry.name)
    return collectors


def write_output(key: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    line = f"{key}={value}\n"
    if output_file:
        with Path(output_file).open("a") as f:
            f.write(line)
    else:
        print(line, end="")


def main() -> None:
    all_collectors = discover_collectors()
    print(f"Total collectors with tests: {len(all_collectors)}")

    for c in all_collectors:
        print(f"  - {c}")

    if not all_collectors:
        print("No collectors to test.")
        write_output("has_tests", "false")
        write_output("matrix", json.dumps({"include": []}, separators=(",", ":")))
        return

    entries = [{"name": c, "collector": c} for c in all_collectors]
    write_output("has_tests", "true")
    write_output("matrix", json.dumps({"include": entries}, separators=(",", ":")))


if __name__ == "__main__":
    main()
