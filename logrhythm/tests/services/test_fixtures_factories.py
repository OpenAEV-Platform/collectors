"""Tests for the test fixture factories themselves.

These guard the factory build helpers against regressions - in particular that
building configuration models does not leak environment-variable state across
tests (which would make the suite order-dependent).
"""

import os

from tests.services.fixtures.factories import (
    ConfigLoaderFactory,
    ConfigLoaderLogRhythmFactory,
    ConfigLoaderOAEVFactory,
)

_MANAGED_ENV_KEYS = [
    "OPENAEV_URL",
    "OPENAEV_TOKEN",
    "LOGRHYTHM_BASE_URL",
    "LOGRHYTHM_TOKEN",
    "LOGRHYTHM_API_VERSION",
    "LOGRHYTHM_MAX_RETRY",
    "LOGRHYTHM_OFFSET",
    "LOGRHYTHM_POLL_INTERVAL",
    "LOGRHYTHM_SEARCH_TIMEOUT",
    "LOGRHYTHM_USERNAME",
    "LOGRHYTHM_PASSWORD",
    "LOGRHYTHM_CONSOLE_URL",
]


def _snapshot_env() -> dict:
    """Capture the current value of every factory-managed env var."""
    return {key: os.environ.get(key) for key in _MANAGED_ENV_KEYS}


def test_config_loader_factory_does_not_leak_env():
    """ConfigLoaderFactory.build restores the environment it mutates."""
    before = _snapshot_env()

    config = ConfigLoaderFactory.build()

    assert config is not None  # noqa: S101
    assert config.logrhythm.token is not None  # noqa: S101
    assert _snapshot_env() == before  # noqa: S101


def test_sub_factories_do_not_leak_env():
    """The OAEV and LogRhythm sub-factories are also side-effect free."""
    before = _snapshot_env()

    assert ConfigLoaderOAEVFactory.build() is not None  # noqa: S101
    assert ConfigLoaderLogRhythmFactory.build() is not None  # noqa: S101

    assert _snapshot_env() == before  # noqa: S101
