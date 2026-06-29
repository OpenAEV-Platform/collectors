"""Tests for DaemonProtocol re-export from collectors_sdk."""

from __future__ import annotations

from typing import Protocol
from unittest.mock import MagicMock

import pytest


def test_daemon_protocol_importable_from_collectors_sdk() -> None:
    """DaemonProtocol is importable from collectors_sdk."""
    from collectors_sdk import DaemonProtocol

    assert DaemonProtocol is not None


def test_daemon_protocol_in_collectors_sdk_all() -> None:
    """DaemonProtocol is listed in collectors_sdk.__all__."""
    import collectors_sdk

    assert "DaemonProtocol" in collectors_sdk.__all__


def test_daemon_protocol_is_runtime_checkable() -> None:
    """DaemonProtocol is a runtime-checkable Protocol."""
    from collectors_sdk import DaemonProtocol

    assert issubclass(DaemonProtocol, Protocol)
    assert getattr(DaemonProtocol, "_is_runtime_protocol", False) is True


def test_daemon_protocol_isinstance_accepts_full_mock() -> None:
    """Mock with start, set_callback, get_id satisfies DaemonProtocol."""
    from collectors_sdk import DaemonProtocol

    mock = MagicMock()
    mock.start = MagicMock()
    mock.set_callback = MagicMock()
    mock.get_id = MagicMock()
    assert isinstance(mock, DaemonProtocol)


@pytest.mark.parametrize("missing", ["start", "set_callback", "get_id"])
def test_daemon_protocol_isinstance_rejects_missing_method(missing: str) -> None:
    """Mock missing any single method fails DaemonProtocol check."""
    from collectors_sdk import DaemonProtocol

    mock = MagicMock()
    mock.start = MagicMock()
    mock.set_callback = MagicMock()
    mock.get_id = MagicMock()
    delattr(mock, missing)
    assert not isinstance(mock, DaemonProtocol)


def test_daemon_protocol_is_same_as_xtm_oaev_sdk() -> None:
    """Re-exported DaemonProtocol is the exact same class from xtm-oaev-sdk."""
    from collectors_sdk import DaemonProtocol as FromCollectors
    from xtm_oaev_sdk import DaemonProtocol as FromSdk

    assert FromCollectors is FromSdk
