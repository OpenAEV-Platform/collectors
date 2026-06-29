"""RED tests for BasicCollectorEngine and __all__ consistency."""

from __future__ import annotations

from unittest.mock import MagicMock

import collectors_sdk
import pytest
from collectors_sdk import (
    BasicCollectorEngine,
    CollectorEngineConfigError,
)


class TestBasicCollectorEngine:
    """BasicCollectorEngine behavioral tests."""

    def test_importable(self) -> None:
        assert BasicCollectorEngine is not None

    def test_run_engine_before_configure_raises(self) -> None:
        """run_engine() must raise CollectorEngineConfigError if not configured."""
        engine = BasicCollectorEngine(
            name="test",
            collector_id="coll-001",
            source=MagicMock(),
            source_handler=MagicMock(),
            oaev_api=MagicMock(),
        )
        with pytest.raises(CollectorEngineConfigError):
            engine.run_engine()


class TestAllConsistency:
    """Bidirectional __all__ consistency."""

    def test_all_symbols_importable(self) -> None:
        for name in collectors_sdk.__all__:
            obj = getattr(collectors_sdk, name, None)
            assert obj is not None, f"{name} listed in __all__ but not importable"

    def test_no_unlisted_exports(self) -> None:
        public = {
            name
            for name in dir(collectors_sdk)
            if not name.startswith("_") and name not in ("annotations",)
        }
        all_set = set(collectors_sdk.__all__)
        # Filter out module-level non-symbols
        leaks = {
            n for n in public - all_set
            if not isinstance(getattr(collectors_sdk, n), type(collectors_sdk))
        }
        assert leaks == set(), f"Exported but not in __all__: {leaks}"
