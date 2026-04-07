#!/usr/bin/env python3
"""
Generate the GitHub Actions test matrix for collector tests.

Discovers collectors with test directories (test/ or tests/) and applies
git-diff filtering to only test collectors that have changed.

Filtering rules (mirrors run_test.sh):
  1. On main or release/current branch       → include all collectors
  2. CI infra files changed                   → include all collectors
  3. Collector directory changed              → include that collector
  4. Otherwise                                → skip
"""

import json
import os
import subprocess
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

CI_INFRA_PATHS = [
    "run_test.sh",
    ".github/scripts/build_test_matrix.py",
    ".github/workflows/tests-collectors.yml",
]


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def get_base_commit() -> str | None:
    release_ref = os.environ.get("RELEASE_REF", "main")
    commit = git("merge-base", f"origin/{release_ref}", "HEAD")
    return commit or None


def has_changes(base_commit: str, *pathspecs: str) -> bool:
    result = subprocess.run(
        ["git", "diff", "--name-only", base_commit, "HEAD", "--", *pathspecs],
        capture_output=True,
        text=True,
    )
    return bool(result.stdout.strip())


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


def should_run(
    collector: str,
    base_commit: str | None,
    is_protected_branch: bool,
    infra_changed: bool,
) -> bool:
    if is_protected_branch or infra_changed:
        return True
    if base_commit is None:
        return True
    return has_changes(base_commit, collector)


def write_output(key: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    line = f"{key}={value}\n"
    if output_file:
        with Path(output_file).open("a") as f:
            f.write(line)
    else:
        print(line, end="")


def main() -> None:
    release_ref = os.environ.get("RELEASE_REF", "main")
    current_branch = os.environ.get("GITHUB_REF_NAME", "")
    is_protected_branch = current_branch in (release_ref, "release/current")

    base_commit = get_base_commit()

    infra_changed = False
    if base_commit and not is_protected_branch:
        infra_changed = has_changes(base_commit, *CI_INFRA_PATHS)

    all_collectors = discover_collectors()
    print(f"Total collectors with tests: {len(all_collectors)}")

    filtered = [
        c
        for c in all_collectors
        if should_run(c, base_commit, is_protected_branch, infra_changed)
    ]

    print(f"Collectors selected for this run: {len(filtered)}")
    for c in filtered:
        print(f"  - {c}")

    if not filtered:
        print("No collectors to test.")
        write_output("has_tests", "false")
        write_output("matrix", json.dumps({"include": []}, separators=(",", ":")))
        return

    entries = [{"name": c, "collector": c} for c in filtered]
    write_output("has_tests", "true")
    write_output("matrix", json.dumps({"include": entries}, separators=(",", ":")))


if __name__ == "__main__":
    main()
