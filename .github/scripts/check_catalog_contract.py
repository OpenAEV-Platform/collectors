#!/usr/bin/env python3
"""
Check that collectors stay in sync with their entry in the OpenAEV catalog.

The platform deploys a collector with the settings of its catalog entry
(``catalog-integrators.json`` in the openaev repository), so a collector change that
the catalog does not follow breaks every catalog deployment while all collector tests
stay green: removing a query placeholder that the catalog default still uses makes the
collector refuse that default at start-up, and a renamed setting is silently ignored.

For each collector directory given on the command line, the matching catalog contract
(found through ``<collector>/manifest-metadata.json``) must satisfy:

1. every setting of the contract is read by the collector, either as a string in its
   sources (pydantic ``alias=`` / ``AliasChoices``, explicit env var names) or as a
   nested pydantic-settings name (``<section>_<field>``) derived from its settings
   models. The base settings that pyoaev defines (``BASE_SETTINGS``) are skipped;
2. every ``{placeholder}`` of a string default belongs to the collector's
   ``ALLOWED_PLACEHOLDERS`` (when the collector defines one).

Everything is read statically: no collector code or dependency is imported.

Usage: check_catalog_contract.py [--catalog PATH_OR_URL] [--changed-since REF] [COLLECTOR_DIR ...]

In CI it runs on the collectors a pull request changes (``--changed-since`` the base
branch), so a change that drifts from the catalog fails its own PR while unrelated PRs
are not blocked by drift that already exists on main.
"""

import argparse
import ast
import json
import os
import string
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CATALOG = (
    "https://raw.githubusercontent.com/OpenAEV-Platform/openaev/main/"
    "openaev-api/src/main/resources/catalog/catalog-integrators.json"
)
CATALOG_ENV = "OPENAEV_CATALOG"
CATALOG_FILE = "openaev-api/src/main/resources/catalog/catalog-integrators.json"
FETCH_TIMEOUT_SECONDS = 30
FETCH_ATTEMPTS = 3

# Settings that pyoaev's base models (or the platform) define for every collector: they
# are not declared in the collector sources, so their absence there proves nothing.
BASE_SETTINGS = {
    "OPENAEV_URL",
    "OPENAEV_TOKEN",
    "OPENAEV_TENANT_ID",
    "COLLECTOR_ID",
    "COLLECTOR_NAME",
    "COLLECTOR_LOG_LEVEL",
    "COLLECTOR_PERIOD",
    "COLLECTOR_PLATFORM",
    "COLLECTOR_ICON_FILEPATH",
}


@dataclass
class _Field:
    names: set[str]
    annotation_types: set[str]


@dataclass
class _Class:
    bases: set[str]
    fields: list[_Field] = field(default_factory=list)


@dataclass
class CollectorSources:
    """What the static analysis of a collector's Python sources found."""

    strings: set[str]
    nested_names: set[str]
    allowed_placeholders: set[str] | None

    def reads(self, setting: str) -> bool:
        key = setting.upper()
        return key in self.strings or key in self.nested_names


def load_catalog(source: str) -> dict:
    """Load the catalog from a local path or an http(s) URL (retried on network errors)."""
    if not source.startswith(("http://", "https://")):
        return json.loads(Path(source).read_text(encoding="utf-8"))
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(
                source, timeout=FETCH_TIMEOUT_SECONDS
            ) as response:
                return json.load(response)
        except OSError:
            if attempt == FETCH_ATTEMPTS:
                raise
            time.sleep(2**attempt)
    raise AssertionError("unreachable")


def changed_collectors(base_ref: str, root: Path = Path(".")) -> list[Path]:
    """Collector directories (those with a manifest) touched since ``base_ref``."""
    diff = subprocess.run(
        ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    top_dirs = {Path(line).parts[0] for line in diff.splitlines() if "/" in line}
    return [
        root / name
        for name in sorted(top_dirs)
        if (root / name / "manifest-metadata.json").is_file()
    ]


def _python_files(collector: Path) -> list[Path]:
    """The collector's runtime sources, tests excluded."""
    return [
        path
        for path in sorted(collector.rglob("*.py"))
        if not {"test", "tests", ".venv", "venv"}
        & set(path.relative_to(collector).parts)
    ]


def _keyword_strings(call: ast.Call, names: tuple[str, ...]) -> set[str]:
    """String values of the given keywords, including AliasChoices(...) arguments."""
    found: set[str] = set()
    for keyword in call.keywords:
        if keyword.arg not in names:
            continue
        for node in ast.walk(keyword.value):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                found.add(node.value)
    return found


def _annotation_types(annotation: ast.expr | None) -> set[str]:
    if annotation is None:
        return set()
    return {node.id for node in ast.walk(annotation) if isinstance(node, ast.Name)}


def _collect_classes(tree: ast.Module, classes: dict[str, _Class]) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        cls = classes.setdefault(node.name, _Class(bases=set()))
        cls.bases |= {base.id for base in node.bases if isinstance(base, ast.Name)}
        for statement in node.body:
            if not (
                isinstance(statement, ast.AnnAssign)
                and isinstance(statement.target, ast.Name)
            ):
                continue
            names = {statement.target.id}
            if isinstance(statement.value, ast.Call):
                names |= _keyword_strings(
                    statement.value, ("alias", "validation_alias")
                )
            cls.fields.append(
                _Field(
                    names=names,
                    annotation_types=_annotation_types(statement.annotation),
                )
            )


def _all_fields(name: str, classes: dict[str, _Class], seen: set[str]) -> list[_Field]:
    """Fields of a class and of its bases defined in the same collector."""
    if name in seen or name not in classes:
        return []
    seen.add(name)
    cls = classes[name]
    fields = list(cls.fields)
    for base in cls.bases:
        fields += _all_fields(base, classes, seen)
    return fields


def _nested_names(classes: dict[str, _Class]) -> set[str]:
    """``<section>_<field>`` names of nested settings models (env_nested_delimiter="_")."""
    names: set[str] = set()
    for cls_name in classes:
        for section in _all_fields(cls_name, classes, set()):
            for section_type in section.annotation_types & classes.keys():
                for sub_field in _all_fields(section_type, classes, set()):
                    names |= {
                        f"{prefix}_{name}".upper()
                        for prefix in section.names
                        for name in sub_field.names
                    }
    return names


def _allowed_placeholders(tree: ast.Module) -> set[str] | None:
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "ALLOWED_PLACEHOLDERS":
                return {
                    item.value
                    for item in ast.walk(value)
                    if isinstance(item, ast.Constant) and isinstance(item.value, str)
                }
    return None


def analyse_collector(collector: Path) -> CollectorSources:
    """Statically read the settings and placeholders a collector understands."""
    strings: set[str] = set()
    classes: dict[str, _Class] = {}
    allowed: set[str] | None = None
    for path in _python_files(collector):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        strings |= {
            node.value.upper()
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        _collect_classes(tree, classes)
        found = _allowed_placeholders(tree)
        if found is not None:
            allowed = (allowed or set()) | found
    return CollectorSources(
        strings=strings,
        nested_names=_nested_names(classes),
        allowed_placeholders=allowed,
    )


def placeholders(template: str) -> set[str]:
    """Top-level ``{placeholder}`` names of a str.format template."""
    try:
        return {
            name.split(".")[0].split("[")[0]
            for _, name, _, _ in string.Formatter().parse(template)
            if name
        }
    except ValueError:
        return set()


def check_collector(
    collector: Path, contracts: dict[str, dict]
) -> tuple[list[str], list[str]]:
    """Return (errors, notes) for one collector directory."""
    manifest = collector / "manifest-metadata.json"
    if not manifest.is_file():
        return [], [f"{collector.name}: no manifest-metadata.json, skipped"]
    slug = json.loads(manifest.read_text(encoding="utf-8")).get("slug")
    contract = contracts.get(slug)
    if contract is None:
        return [], [f"{collector.name}: no catalog entry for slug '{slug}', skipped"]

    sources = analyse_collector(collector)
    properties = contract.get("config_schema", {}).get("properties", {})
    errors: list[str] = []
    notes: list[str] = []
    for key, prop in properties.items():
        if key.upper() not in BASE_SETTINGS and not sources.reads(key):
            errors.append(
                f"{collector.name}: catalog setting '{key}' is not read by the "
                "collector (renamed or removed?): update the collector, or the "
                f"'{slug}' entry of openaev {CATALOG_FILE}"
            )
        default = prop.get("default")
        used = placeholders(default) if isinstance(default, str) else set()
        if not used:
            continue
        if sources.allowed_placeholders is None:
            notes.append(
                f"{collector.name}: '{key}' default uses placeholders but the "
                "collector defines no ALLOWED_PLACEHOLDERS, not checked"
            )
            continue
        unknown = used - sources.allowed_placeholders
        if unknown:
            errors.append(
                f"{collector.name}: the catalog default of '{key}' uses "
                f"{sorted(unknown)}, which the collector rejects (allowed: "
                f"{sorted(sources.allowed_placeholders)}): update the '{slug}' "
                f"entry of openaev {CATALOG_FILE}"
            )
    if not errors:
        notes.append(f"{collector.name}: OK ({len(properties)} catalog settings)")
    return errors, notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument(
        "--catalog",
        default=os.environ.get(CATALOG_ENV, DEFAULT_CATALOG),
        help=f"catalog path or URL (default: ${CATALOG_ENV} or openaev main)",
    )
    parser.add_argument(
        "--changed-since",
        metavar="REF",
        help="also check the collectors changed between REF and HEAD",
    )
    parser.add_argument("collectors", nargs="*", type=Path)
    args = parser.parse_args(argv)

    collectors = list(args.collectors)
    if args.changed_since:
        collectors += changed_collectors(args.changed_since)
    if not collectors:
        print("No collector to check.")
        return 0
    try:
        catalog = load_catalog(args.catalog)
    except (OSError, ValueError) as err:
        print(
            f"::error::Could not load the OpenAEV catalog from {args.catalog}: {err}. "
            "Re-run the job; the check cannot pass without the catalog.",
            file=sys.stderr,
        )
        return 2
    contracts = {c.get("slug"): c for c in catalog.get("contracts", [])}

    failed = False
    for collector in dict.fromkeys(collectors):
        errors, notes = check_collector(collector, contracts)
        for note in notes:
            print(note)
        for error in errors:
            print(f"::error::{error}")
        failed |= bool(errors)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
