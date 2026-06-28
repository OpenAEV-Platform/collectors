"""Tests for the test fixture factories themselves.

These guard the factory build helpers against regressions - in particular that
building configuration models does not leak environment-variable state across
tests (which would make the suite order-dependent).
"""

import os

from tests.services.fixtures.factories import (
    ConfigLoaderFactory,
    ConfigLoaderNetWitnessFactory,
    ConfigLoaderOAEVFactory,
)

_MANAGED_ENV_KEYS = [
    "OPENAEV_URL",
    "OPENAEV_TOKEN",
    "NETWITNESS_BASE_URL",
    "NETWITNESS_USERNAME",
    "NETWITNESS_PASSWORD",
    "NETWITNESS_MAX_RETRY",
    "NETWITNESS_OFFSET",
    "NETWITNESS_TOKEN",
    "NETWITNESS_CONSOLE_URL",
]


def _snapshot_env() -> dict:
    """Capture the current value of every factory-managed env var."""
    return {key: os.environ.get(key) for key in _MANAGED_ENV_KEYS}


def test_config_loader_factory_does_not_leak_env():
    """ConfigLoaderFactory.build restores the environment it mutates."""
    before = _snapshot_env()

    config = ConfigLoaderFactory.build()

    assert config is not None  # noqa: S101
    assert config.netwitness.username is not None  # noqa: S101
    assert _snapshot_env() == before  # noqa: S101


def test_sub_factories_do_not_leak_env():
    """The OAEV and NetWitness sub-factories are also side-effect free."""
    before = _snapshot_env()

    assert ConfigLoaderOAEVFactory.build() is not None  # noqa: S101
    assert ConfigLoaderNetWitnessFactory.build() is not None  # noqa: S101

    assert _snapshot_env() == before  # noqa: S101
