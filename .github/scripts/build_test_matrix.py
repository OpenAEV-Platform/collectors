#!/usr/bin/env python3
"""
Generate the GitHub Actions matrices for the collector workflows.

- ``matrix`` / ``has_tests``: every collector with a test directory (test/ or tests/).
  All collectors with tests are always tested.
- ``runtime_matrix`` / ``has_shipped``: every collector that ships as an image (a
  pyproject.toml plus a Dockerfile), once per Python version its Dockerfiles ship, for the
  pinned-runtime smoke job.
"""

import json
import os
import re
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

# Every Dockerfile a collector is published from; each one may ship its own Python.
IMAGE_DOCKERFILES = ("Dockerfile", "Dockerfile_ubi9")

# ARG NAME=value (defaults that a later FROM line may reference)
_ARG_DEFAULT = re.compile(r"^\s*ARG\s+(?P<name>\w+)=(?P<value>\S+)", re.IGNORECASE)
_ARG_REFERENCE = re.compile(r"\$\{(?P<braced>\w+)\}|\$(?P<bare>\w+)")
# FROM [--platform=...] [registry[:port]/][namespace/]python:X.Y[-variant] [AS stage]
_FROM_PYTHON = re.compile(
    r"^\s*FROM\s+(?:--\S+\s+)*(?:[\w.-]+(?::\d+)?/)*python:(?P<version>\d+\.\d+)",
    re.IGNORECASE,
)
# Package installs of an interpreter, e.g. "microdnf install python3.14" in the ubi9 images.
_INSTALL = re.compile(r"\binstall\b", re.IGNORECASE)
_PYTHON_PACKAGE = re.compile(r"\bpython(?P<version>\d+\.\d+)\b", re.IGNORECASE)


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _expand_args(line: str, args: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group("braced") or match.group("bare")
        return args.get(name, match.group(0))

    return _ARG_REFERENCE.sub(replace, line)


def dockerfile_python_versions(text: str) -> list[str]:
    """Python versions a Dockerfile ships, sorted numerically.

    Read from ``FROM python:X.Y`` base images (after expanding ``ARG`` defaults) and from
    package installs of ``pythonX.Y`` (how the ubi9 images get their interpreter).
    """
    versions: set[str] = set()
    args: dict[str, str] = {}
    for line in text.splitlines():
        arg = _ARG_DEFAULT.match(line)
        if arg:
            args[arg["name"]] = arg["value"].strip("\"'")
            continue
        expanded = _expand_args(line, args)
        base_image = _FROM_PYTHON.match(expanded)
        if base_image:
            versions.add(base_image["version"])
        if _INSTALL.search(expanded):
            versions.update(m["version"] for m in _PYTHON_PACKAGE.finditer(expanded))
    return sorted(versions, key=_version_key)


def image_python_versions(collector: Path) -> list[str]:
    """Every Python version the collector's Dockerfiles ship, across all image flavours."""
    versions: set[str] = set()
    for name in IMAGE_DOCKERFILES:
        dockerfile = collector / name
        if dockerfile.is_file():
            text = dockerfile.read_text(encoding="utf-8")
            versions.update(dockerfile_python_versions(text))
    return sorted(versions, key=_version_key)


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


def discover_shipped_collectors() -> list[dict[str, str]]:
    """One runtime-matrix entry per (collector, Python version) for every shipped collector.

    A collector ships when it has a pyproject.toml plus at least one of IMAGE_DOCKERFILES.
    These feed the pinned-runtime smoke job, which must cover collectors WITHOUT a test
    suite too - the runtime/pyoaev drift it guards against does not depend on tests
    existing. A collector whose Dockerfiles yield no Python version still gets one entry,
    with an empty ``python``, so its smoke job fails loudly instead of silently vanishing
    from the matrix.
    """
    entries = []
    for entry in _candidate_dirs():
        if not (entry / "pyproject.toml").is_file():
            continue
        if not any((entry / name).is_file() for name in IMAGE_DOCKERFILES):
            continue
        for version in image_python_versions(entry) or [""]:
            name = f"{entry.name} py{version}" if version else entry.name
            entries.append({"name": name, "collector": entry.name, "python": version})
    return entries


def write_output(key: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    line = f"{key}={value}\n"
    if output_file:
        with Path(output_file).open("a") as f:
            f.write(line)
    else:
        print(line, end="")


def write_matrix(key: str, flag_key: str, entries: list[dict[str, str]]) -> None:
    write_output(flag_key, "true" if entries else "false")
    write_output(key, json.dumps({"include": entries}, separators=(",", ":")))


def main() -> None:
    all_collectors = discover_collectors()
    print(f"Total collectors with tests: {len(all_collectors)}")

    for c in all_collectors:
        print(f"  - {c}")

    if not all_collectors:
        print("No collectors to test.")
    write_matrix(
        "matrix", "has_tests", [{"name": c, "collector": c} for c in all_collectors]
    )

    shipped = discover_shipped_collectors()
    print(
        f"Total pinned-runtime smoke entries (collector x image Python): {len(shipped)}"
    )
    for entry in shipped:
        print(f"  - {entry['name']}")
        if not entry["python"]:
            print(
                f"    WARNING: no Python version found in {entry['collector']}/"
                f"{' or '.join(IMAGE_DOCKERFILES)}; its smoke job will fail"
            )
    write_matrix("runtime_matrix", "has_shipped", shipped)


if __name__ == "__main__":
    main()
