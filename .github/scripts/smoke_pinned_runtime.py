#!/usr/bin/env python3
"""Smoke-test a collector against the pyoaev release it PINS, on the interpreter its image ships.

Why this exists: the collector images resolve ``pyoaev`` from PyPI at the version pinned in
``pyproject.toml`` (``poetry install --only main --no-root``), while ``run_test.sh`` force-installs
pyoaev from git ``main`` before running the test suites. The two can drift silently: every image
from 3.260917.0 to 3.260921.0 shipped Python 3.14 with pyoaev 3.260904.0, whose
``RESTObject._create_managers`` reads ``self.__annotations__`` - an attribute Python 3.14 (PEP
649/749 deferred annotations) no longer exposes on instances - so every collector died in
``CollectorDaemon._setup`` on ``api.collector.create(...)`` while its ``PingAlive`` thread kept the
platform believing it was healthy. No test caught it: the suites mock the API and ran against a
pyoaev that already carried the fix.

This script must run INSIDE the collector's Poetry environment right after the same install
command the Dockerfile runs, never after the git override::

    cd <collector> && poetry install --only main --no-root
    poetry run python ../.github/scripts/smoke_pinned_runtime.py .

It checks, on the interpreter and pyoaev release that will actually run in production:

1. every ``RESTObject`` subclass under ``pyoaev.apis`` can be instantiated (the code path that
   builds the response of ``api.collector.create`` at collector start-up);
2. every package the collector declares in ``[tool.poetry].packages`` imports.

Exit code 1 on any failure, with one line per failure.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import sys
import tomllib
import types
from pathlib import Path


def _stub_manager() -> types.SimpleNamespace:
    """The minimum ``RESTManager`` surface ``RESTObject.__init__`` touches."""
    return types.SimpleNamespace(parent_attrs={}, openaev=None, path="/smoke")


def smoke_rest_objects() -> tuple[int, list[str]]:
    """Instantiate every REST object pyoaev ships; return (checked, failures)."""
    from pyoaev import apis
    from pyoaev.base import RESTObject

    checked = 0
    failures: list[str] = []
    for module_info in pkgutil.walk_packages(apis.__path__, apis.__name__ + "."):
        try:
            module = importlib.import_module(module_info.name)
        except (
            Exception
        ) as exc:  # noqa: BLE001 - report every failure, never stop early
            failures.append(f"import {module_info.name}: {exc!r}")
            continue
        for name, cls in inspect.getmembers(module, inspect.isclass):
            if (
                not issubclass(cls, RESTObject)
                or cls is RESTObject
                or cls.__module__ != module.__name__
            ):
                continue
            try:
                cls(manager=_stub_manager(), attrs={"id": "smoke"})
                checked += 1
            except Exception as exc:  # noqa: BLE001
                failures.append(f"instantiate {module.__name__}.{name}: {exc!r}")
    return checked, failures


def declared_packages(collector_dir: Path) -> list[str]:
    """Package names declared under ``[tool.poetry].packages`` in the collector pyproject."""
    with (collector_dir / "pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)
    packages = pyproject.get("tool", {}).get("poetry", {}).get("packages", [])
    return [
        entry["include"]
        for entry in packages
        if isinstance(entry, dict) and "include" in entry
    ]


def smoke_collector_imports(collector_dir: Path) -> tuple[int, list[str]]:
    """Import every declared collector package from the collector directory."""
    sys.path.insert(0, str(collector_dir))
    checked = 0
    failures: list[str] = []
    for package in declared_packages(collector_dir):
        try:
            importlib.import_module(package)
            checked += 1
        except Exception as exc:  # noqa: BLE001
            failures.append(f"import collector package {package}: {exc!r}")
    return checked, failures


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: smoke_pinned_runtime.py <collector-dir>", file=sys.stderr)
        return 2
    collector_dir = Path(argv[1]).resolve()
    if not (collector_dir / "pyproject.toml").is_file():
        print(f"{collector_dir} has no pyproject.toml", file=sys.stderr)
        return 2

    try:
        import pyoaev
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL pyoaev is not importable in this environment: {exc!r}")
        return 1

    print(
        f"python {sys.version.split()[0]} / pyoaev {getattr(pyoaev, '__version__', '?')}"
        f" / collector {collector_dir.name}"
    )

    objects_checked, failures = smoke_rest_objects()
    print(f"pyoaev REST objects instantiated: {objects_checked}")
    packages_checked, package_failures = smoke_collector_imports(collector_dir)
    print(f"collector packages imported: {packages_checked}")
    failures.extend(package_failures)

    if objects_checked == 0:
        failures.append("no pyoaev REST object was found under pyoaev.apis")
    if packages_checked == 0:
        failures.append("no collector package is declared under [tool.poetry].packages")

    for failure in failures:
        print(f"FAIL {failure}")
    if failures:
        print(
            "The pyoaev release pinned in pyproject.toml is not usable on the interpreter the"
            " Dockerfile ships - bump the pin (or the base image) before releasing."
        )
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
