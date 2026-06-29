"""RED tests for BaseCollector."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from collectors_sdk import BaseCollector


class TestBaseCollector:
    """BaseCollector lifecycle tests."""

    def test_importable(self) -> None:
        assert BaseCollector is not None

    def test_has_setup_method(self) -> None:
        assert hasattr(BaseCollector, "_setup")
