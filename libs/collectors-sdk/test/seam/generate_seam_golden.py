"""Fingerprint every public object of the collectors-sdk seam and update the golden.

Discovery is dynamic: every ``*.py`` file under ``collectors_sdk/seam`` is parsed, and
every public top-level definition (class, function, assignment) gets a sha256 of:

- its normalized AST: formatting, comments and docstrings are ignored, so the hash
  moves only when the definition itself changes (fields, defaults, enum members,
  signatures, validators, constant values...);
- for pydantic models, their validation and serialization JSON schemas too, which
  also catch what reaches the wire through the types they reference.

Run from ``libs/collectors-sdk`` after a deliberate seam change, together with the
``SEAM_VERSION`` bump of the capability::

    python test/seam/generate_seam_golden.py

It rewrites ``fixtures/seam_golden.json``: changed fingerprints are updated, new
objects added, and objects that no longer exist removed. ``test_seam_golden.py``
fails on any difference between the golden and the code.
"""

import ast
import copy
import hashlib
import importlib
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import collectors_sdk.seam

SEAM_ROOT = Path(collectors_sdk.seam.__file__).parent
PACKAGE_ROOT = SEAM_ROOT.parent.parent
GOLDEN_PATH = Path(__file__).parent / "fixtures" / "seam_golden.json"

_IGNORED_AST_FIELDS = {"ctx", "type_comment"}
_DOCSTRING_OWNERS = (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)


def _module_name(path: Path) -> str:
    parts = path.relative_to(PACKAGE_ROOT).with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _defined_names(node: ast.stmt) -> list[str]:
    if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
        return [node.name]
    if isinstance(node, ast.Assign):
        return [t.id for t in node.targets if isinstance(t, ast.Name)]
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return [node.target.id]
    if isinstance(node, ast.TypeAlias):
        return [node.name.id]
    return []


def _without_docstrings(node: ast.stmt) -> ast.stmt:
    node = copy.deepcopy(node)
    for child in ast.walk(node):
        if isinstance(child, _DOCSTRING_OWNERS) and child.body:
            first = child.body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                child.body = child.body[1:]
    return node


def _canonical_ast(node: Any) -> str:
    """Python-version-stable text of an AST: no positions, no empty fields."""
    if isinstance(node, ast.AST):
        fields = []
        for field in node._fields:
            if field in _IGNORED_AST_FIELDS:
                continue
            value = getattr(node, field, None)
            if value is None or value == []:
                continue
            fields.append(f"{field}={_canonical_ast(value)}")
        return f"{type(node).__name__}({', '.join(fields)})"
    if isinstance(node, list):
        return "[" + ", ".join(_canonical_ast(item) for item in node) + "]"
    return repr(node)


def _pydantic_schemas(obj: Any) -> str | None:
    from pydantic import BaseModel

    if not (isinstance(obj, type) and issubclass(obj, BaseModel)):
        return None
    schemas = {
        mode: obj.model_json_schema(mode=mode)
        for mode in ("validation", "serialization")
    }
    return json.dumps(schemas, sort_keys=True)


def iter_seam_definitions() -> Iterator[tuple[str, str, ast.stmt, Any]]:
    """Every public top-level definition of the seam: (module, name, node, object)."""
    for path in sorted(SEAM_ROOT.rglob("*.py")):
        module_name = _module_name(path)
        module = importlib.import_module(module_name)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            for name in _defined_names(node):
                if not name.startswith("_"):
                    yield module_name, name, node, getattr(module, name)


def _kind(node: ast.stmt, obj: Any) -> str:
    if _pydantic_schemas(obj) is not None:
        return "pydantic model"
    if isinstance(node, ast.ClassDef):
        return "class"
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return "function"
    return "assignment"


def compute_seam_fingerprints() -> dict[str, dict[str, str]]:
    """``{"<module>.<name>": {"kind": ..., "sha256": ...}}`` for the whole seam."""
    fingerprints = {}
    for module_name, name, node, obj in iter_seam_definitions():
        text = "ast:" + _canonical_ast(_without_docstrings(node))
        schemas = _pydantic_schemas(obj)
        if schemas is not None:
            text += "\nschemas:" + schemas
        fingerprints[f"{module_name}.{name}"] = {
            "kind": _kind(node, obj),
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
        }
    return dict(sorted(fingerprints.items()))


def diff_fingerprints(
    golden: dict[str, dict[str, str]], current: dict[str, dict[str, str]]
) -> dict[str, list[str]]:
    """Seam objects added, removed and changed since the golden."""
    return {
        "added": sorted(current.keys() - golden.keys()),
        "removed": sorted(golden.keys() - current.keys()),
        "changed": sorted(
            key
            for key in current.keys() & golden.keys()
            if current[key]["sha256"] != golden[key]["sha256"]
        ),
    }


def _capability(key: str) -> str:
    return key.split(".")[2]


def _unversioned_capabilities(diff: dict[str, list[str]]) -> list[str]:
    touched = {_capability(key) for keys in diff.values() for key in keys}
    bumped = {
        _capability(key)
        for keys in diff.values()
        for key in keys
        if key.rsplit(".", 1)[1].endswith("VERSION")
    }
    return sorted(touched - bumped)


def main() -> int:
    golden = json.loads(GOLDEN_PATH.read_text()) if GOLDEN_PATH.exists() else {}
    current = compute_seam_fingerprints()
    diff = diff_fingerprints(golden, current)
    for change, keys in diff.items():
        for key in keys:
            print(f"{change:8} {key}")
    for capability in _unversioned_capabilities(diff):
        print(
            f"WARNING  the {capability} seam changed but its version did not: "
            "bump it if this is a contract change."
        )
    GOLDEN_PATH.write_text(json.dumps(current, indent=2) + "\n")
    print(f"wrote {len(current)} fingerprints to {GOLDEN_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
