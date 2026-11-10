"""The seam golden: every public seam object is fingerprinted, and any drift fails.

The fingerprints come from ``generate_seam_golden.py``, which discovers the seam
dynamically (every ``*.py`` file, every public top-level definition). On a failure,
``git diff`` the objects listed: they are exactly what changed. If the change is
deliberate, bump the capability's ``SEAM_VERSION``, then run, from ``libs/collectors-sdk``::

    python test/seam/generate_seam_golden.py
"""

import importlib.util
import inspect
import json
from pathlib import Path
from types import ModuleType

import collectors_sdk

_GENERATOR = Path(__file__).parent / "generate_seam_golden.py"


def _given_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_seam_golden", _GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _given_golden(generator: ModuleType) -> dict[str, dict[str, str]]:
    return json.loads(generator.GOLDEN_PATH.read_text())


def _when_fingerprinting_the_seam(generator: ModuleType) -> dict[str, dict[str, str]]:
    return generator.compute_seam_fingerprints()


def _then_no_drift(diff: dict[str, list[str]]) -> None:
    drift = [f"{change}: {key}" for change, keys in diff.items() for key in keys]
    assert not drift, (
        "The seam drifted from its golden:\n  "
        + "\n  ".join(drift)
        + "\nIf deliberate: bump the capability's version, then run "
        "`python test/seam/generate_seam_golden.py` from libs/collectors-sdk."
    )


def test_seam_matches_its_golden() -> None:
    """It fails on any seam object added, removed or changed since the golden."""
    generator = _given_generator()
    golden = _given_golden(generator)
    current = _when_fingerprinting_the_seam(generator)
    _then_no_drift(generator.diff_fingerprints(golden, current))


def test_root_reexports_are_the_seam_objects() -> None:
    """It hands out, from the package root, the very objects the seam defines."""
    generator = _given_generator()
    broken = [
        f"{module}.{name}"
        for module, name, _, obj in generator.iter_seam_definitions()
        if (inspect.isclass(obj) or inspect.isfunction(obj))
        and hasattr(collectors_sdk, name)
        and getattr(collectors_sdk, name) is not obj
    ]
    assert not broken, f"Root re-exports are not the seam objects: {broken}"
