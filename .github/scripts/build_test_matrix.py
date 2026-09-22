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


def _candidate_dirs() -> list[Path]:
    return [
        entry
        for entry in sorted(Path(".").iterdir())
        if entry.is_dir()
        and not entry.name.startswith(".")
        and entry.name not in EXCLUDED_DIRS
    ]


def discover_collectors() -> list[str]:
    """Find all collector directories that contain test/ or tests/ subdirectories."""
    return [
        entry.name
        for entry in _candidate_dirs()
        if (entry / "test").is_dir() or (entry / "tests").is_dir()
    ]


def discover_shipped_collectors() -> list[str]:
    """Find every collector that ships as an image: a pyproject.toml plus a Dockerfile.

    These feed the pinned-runtime smoke job, which must cover collectors WITHOUT a test
    suite too - the runtime/pyoaev drift it guards against does not depend on tests existing.
    """
    return [
        entry.name
        for entry in _candidate_dirs()
        if (entry / "pyproject.toml").is_file() and (entry / "Dockerfile").is_file()
    ]


def write_output(key: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    line = f"{key}={value}\n"
    if output_file:
        with Path(output_file).open("a") as f:
            f.write(line)
    else:
        print(line, end="")


def write_matrix(key: str, flag_key: str, collectors: list[str]) -> None:
    entries = [{"name": c, "collector": c} for c in collectors]
    write_output(flag_key, "true" if collectors else "false")
    write_output(key, json.dumps({"include": entries}, separators=(",", ":")))


def main() -> None:
    all_collectors = discover_collectors()
    print(f"Total collectors with tests: {len(all_collectors)}")

    for c in all_collectors:
        print(f"  - {c}")

    if not all_collectors:
        print("No collectors to test.")
    write_matrix("matrix", "has_tests", all_collectors)

    shipped_collectors = discover_shipped_collectors()
    print(f"Total shipped collectors (pinned-runtime smoke): {len(shipped_collectors)}")
    for c in shipped_collectors:
        print(f"  - {c}")
    write_matrix("runtime_matrix", "has_shipped", shipped_collectors)


if __name__ == "__main__":
    main()
