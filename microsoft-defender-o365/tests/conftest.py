"""Shared pytest fixtures for the Defender O365 collector BDD-style tests.

These fixtures are designed to be reused across every tests/features and
tests/constraints scenario module, following the Given/When/Then helper
convention described in the project's CONTRIBUTING.md.
"""

from types import ModuleType

import pytest
from polyfactory.factories.pydantic_factory import ModelFactory
from pydantic import BaseModel


class CollectorRegistrationConfig(BaseModel):
    """Payload mirroring what the collector registers into the OpenAEV catalog.

    Mirrors the fields sent by ``CollectorDaemon._setup()`` (from ``pyoaev``)
    when a collector registers itself into the platform catalog.
    """

    collector_id: str
    collector_name: str
    collector_type: str
    collector_period: int
    status: str = "Deployed"


class CollectorRegistrationConfigFactory(ModelFactory[CollectorRegistrationConfig]):
    """Polyfactory factory generating dynamic CollectorRegistrationConfig fixtures."""

    __model__ = CollectorRegistrationConfig


@pytest.fixture
def collector_registration_config_factory() -> type[CollectorRegistrationConfigFactory]:
    """Expose the polyfactory factory so feature tests can build dynamic fixtures."""
    return CollectorRegistrationConfigFactory


@pytest.fixture
def microsoft_defender_o365_collector_module() -> ModuleType:
    """Import and expose the (not-yet-implemented) collector entry-point module.

    This module is expected to be created by chunk1 (#471) as
    ``src/microsoft_defender_o365_collector.py``, exposing a ``main()`` function
    wiring a stub ``Source`` into ``BaseCollector``. Importing it is expected to
    fail until that implementation lands, which is the intended "red" state of
    these tests.
    """
    import src.microsoft_defender_o365_collector as module

    return module
