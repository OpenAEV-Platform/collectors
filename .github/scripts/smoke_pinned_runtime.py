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
pyoaev that already carried the fix. The release builds also carry a ``PYOAEV_GIT_REF_OVERRIDE``
build argument meant to force-install client-python at the release tag, but it was a no-op on
every one of those releases (wrong argument name, and never set on tag builds) - the pin is what
runs whenever that override is absent or fails silently, so the pin is what this script checks.

This script must run INSIDE the collector's Poetry environment right after the same install
command the Dockerfile runs, never after the git override::

    cd <collector> && poetry install --only main --no-root
    poetry run python ../.github/scripts/smoke_pinned_runtime.py .

It checks, on the interpreter and pyoaev release that will actually run in production:

1. every ``RESTObject`` subclass under ``pyoaev.apis`` can be instantiated (the code path that
   builds the response of ``api.collector.create`` at collector start-up);
2. the collector's own start-up imports: every package declared under ``[tool.poetry].packages``
   and the module behind every ``[project.scripts]`` entry point (``<package>.__main__``, which
   is what ``python -m <package>`` imports before it calls ``main()``).

Exit code 1 on any failure, with one line per failure and a remedy per failure class (pyoaev pin
vs collector code); 2 on usage errors.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import sys
import tomllib
import types
from pathlib import Path
from typing import Any

PYOAEV_REMEDY = (
    "The pyoaev release pinned in pyproject.toml does not work on the interpreter the"
    " Dockerfile ships - bump the pin (or the base image) before releasing."
)
COLLECTOR_REMEDY = (
    "The collector's own start-up imports fail on the interpreter and dependencies the"
    " Dockerfile ships - fix the collector (or its dependency constraints) before"
    " releasing."
)


def _stub_manager() -> types.SimpleNamespace:
    """The minimum ``RESTManager`` surface a ``RESTObject`` reads while it is built.

    ``parent_attrs`` is copied onto the object and ``openaev`` (the client) is handed to the
    child managers ``_create_managers`` instantiates - the exact step that crashed.
    """
    return types.SimpleNamespace(parent_attrs={}, openaev=None, path="/smoke")


def smoke_rest_objects() -> tuple[int, list[str]]:
    """Instantiate every REST object pyoaev ships; return ``(checked, failures)``."""
    try:
        from pyoaev import apis
        from pyoaev.base import RESTObject
    except Exception as exc:  # broad on purpose: any exception is a finding to report
        return 0, [f"import pyoaev.apis: {exc!r}"]

    checked = 0
    failures: list[str] = []
    failed_imports: set[str] = set()

    def record_import_failure(name: str, exc: BaseException | None) -> None:
        if name not in failed_imports:
            failed_imports.add(name)
            failures.append(f"import {name}: {exc!r}")

    def on_walk_error(name: str) -> None:
        # pkgutil calls this from inside its ``except`` clause while importing a sub-package
        # to recurse into it. Without a handler an ImportError silently drops the whole
        # sub-tree from the walk (under-counting) and any other exception aborts it.
        record_import_failure(name, sys.exception())

    modules = pkgutil.walk_packages(
        apis.__path__, apis.__name__ + ".", onerror=on_walk_error
    )
    for module_info in modules:
        try:
            module = importlib.import_module(module_info.name)
        except Exception as exc:  # broad on purpose: report it and keep walking
            record_import_failure(module_info.name, exc)
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
            except Exception as exc:  # broad on purpose: report every object
                failures.append(f"instantiate {module.__name__}.{name}: {exc!r}")
            else:
                checked += 1
    return checked, failures


def load_pyproject(collector_dir: Path) -> dict[str, Any]:
    with (collector_dir / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def declared_packages(pyproject: dict[str, Any]) -> list[str]:
    """Package names declared under ``[tool.poetry].packages``."""
    packages = pyproject.get("tool", {}).get("poetry", {}).get("packages", [])
    return [
        entry["include"]
        for entry in packages
        if isinstance(entry, dict) and "include" in entry
    ]


def entry_points(pyproject: dict[str, Any]) -> list[tuple[str, str, str]]:
    """``(script, module, attribute)`` for every ``module:attribute`` in ``[project.scripts]``."""
    scripts = pyproject.get("project", {}).get("scripts", {})
    result = []
    for script, target in scripts.items():
        module, _, attribute = str(target).partition(":")
        result.append((script, module, attribute))
    return result


def pinned_pyoaev(pyproject: dict[str, Any]) -> str:
    """The pyoaev constraint declared in ``[tool.poetry.dependencies]`` (``?`` when absent)."""
    dependencies = pyproject.get("tool", {}).get("poetry", {}).get("dependencies", {})
    spec = dependencies.get("pyoaev", "?")
    if isinstance(spec, dict):
        spec = spec.get("version", "?")
    return str(spec)


def smoke_collector_imports(
    collector_dir: Path, pyproject: dict[str, Any]
) -> tuple[int, list[str]]:
    """Import the collector the way its image starts it; return ``(checked, failures)``.

    ``poetry install --no-root`` does not install the collector itself, so the collector
    directory goes on ``sys.path`` exactly as ``WORKDIR /collector`` puts it there for
    ``python -m <package>`` in the image.
    """
    sys.path.insert(0, str(collector_dir))
    checked = 0
    failures: list[str] = []
    for package in declared_packages(pyproject):
        try:
            importlib.import_module(package)
        except Exception as exc:  # broad on purpose: report every package
            failures.append(f"import collector package {package}: {exc!r}")
        else:
            checked += 1
    for script, module_name, attribute in entry_points(pyproject):
        # ``python -m <package>`` imports ``<package>.__main__`` and only then calls
        # ``main()`` under the ``__name__`` guard: importing the module runs the same
        # start-up imports without starting the collector.
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # broad on purpose: report every entry point
            failures.append(f"import entry point {script} ({module_name}): {exc!r}")
            continue
        if not hasattr(module, attribute):
            failures.append(
                f"entry point {script}: {module_name} has no attribute {attribute!r}"
            )
            continue
        checked += 1
    return checked, failures


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: smoke_pinned_runtime.py <collector-dir>", file=sys.stderr)
        return 2
    collector_dir = Path(argv[1]).resolve()
    if not (collector_dir / "pyproject.toml").is_file():
        print(f"{collector_dir} has no pyproject.toml", file=sys.stderr)
        return 2
    pyproject = load_pyproject(collector_dir)

    try:
        import pyoaev
    except Exception as exc:  # broad on purpose: any exception is the finding
        print(f"FAIL pyoaev is not importable in this environment: {exc!r}")
        print(PYOAEV_REMEDY)
        return 1

    installed = getattr(pyoaev, "__version__", "?")
    print(
        f"python {sys.version.split()[0]} / pyoaev {installed}"
        f" (pinned {pinned_pyoaev(pyproject)}) / collector {collector_dir.name}"
    )

    objects_checked, pyoaev_failures = smoke_rest_objects()
    print(f"pyoaev REST objects instantiated: {objects_checked}")
    if objects_checked == 0 and not pyoaev_failures:
        pyoaev_failures.append("no pyoaev REST object was found under pyoaev.apis")

    imports_checked, collector_failures = smoke_collector_imports(
        collector_dir, pyproject
    )
    print(f"collector packages and entry points imported: {imports_checked}")
    if imports_checked == 0 and not collector_failures:
        collector_failures.append(
            "nothing to import: no [tool.poetry].packages and no [project.scripts] entry"
        )

    for failure in pyoaev_failures + collector_failures:
        print(f"FAIL {failure}")
    if pyoaev_failures:
        print(PYOAEV_REMEDY)
    if collector_failures:
        print(COLLECTOR_REMEDY)
    if pyoaev_failures or collector_failures:
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
