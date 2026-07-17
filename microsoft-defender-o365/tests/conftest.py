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


# --------
# Chunk2 (#493) - business configuration (source_configs.py) shared helpers
# --------
#
# Per RULE-0006 (~/.copilot/rules/0006-template-placeholder-replacement-over-new-class.md),
# chunk2's Done Checklist names a "DefenderO365Config" class, but the target file
# (src/models/settings/source_configs.py) already holds the template's placeholder scaffold
# class `_ConfigLoaderSource(ConfigBaseSettings)`. The resolution is to keep the template's
# class name/structure and replace only its placeholder fields/aliases with the real business
# fields below, rather than introducing a differently-named class. Gherkin `When ... DefenderO365Config
# is instantiated` steps are therefore implemented against `_ConfigLoaderSource`.

MICROSOFT_DEFENDER_O365_ENV_PREFIX = "MICROSOFT_DEFENDER_O365_"

#: Minimal set of env vars that make `_ConfigLoaderSource` instantiate without error.
MICROSOFT_DEFENDER_O365_VALID_REQUIRED_ENV: dict[str, str] = {
    "TENANT_ID": "test-tenant-id",
    "CLIENT_ID": "test-client-id",
    "CLIENT_SECRET": "test-client-secret",
}


@pytest.fixture
def microsoft_defender_o365_source_config_module() -> ModuleType:
    """Import and expose the (not-yet-implemented) source configuration module.

    This module is expected to be updated by chunk2 (#493) so that
    ``src.models.settings.source_configs._ConfigLoaderSource`` carries the real
    Microsoft Defender for Office 365 business configuration fields (``tenant_id``,
    ``client_id``, ``use_certificate_auth``, ...) instead of the template's generic
    placeholders. Importing it and instantiating the class is expected to fail/raise
    the wrong errors until that implementation lands, which is the intended "red"
    state of these tests.
    """
    import src.models.settings.source_configs as module

    return module


def _given_microsoft_defender_o365_env_var_set(
    monkeypatch, field_name: str, value: str
) -> None:
    """Given MICROSOFT_DEFENDER_O365_<FIELD> is set to "<value>".

    Args:
        monkeypatch: pytest's monkeypatch fixture.
        field_name: The field's env var suffix (e.g. ``"TENANT_ID"``), appended to
            ``MICROSOFT_DEFENDER_O365_ENV_PREFIX``.
        value: The value to set the env var to.

    """
    monkeypatch.setenv(f"{MICROSOFT_DEFENDER_O365_ENV_PREFIX}{field_name}", value)


def _given_microsoft_defender_o365_env_var_not_set(monkeypatch, field_name: str) -> None:
    """Given MICROSOFT_DEFENDER_O365_<FIELD> is not set.

    Args:
        monkeypatch: pytest's monkeypatch fixture.
        field_name: The field's env var suffix (e.g. ``"CLIENT_CERT_PATH"``), appended
            to ``MICROSOFT_DEFENDER_O365_ENV_PREFIX``.

    """
    monkeypatch.delenv(f"{MICROSOFT_DEFENDER_O365_ENV_PREFIX}{field_name}", raising=False)


def _given_microsoft_defender_o365_all_required_fields_present(
    monkeypatch, exclude: str | None = None
) -> None:
    """Given all other required fields are present / all required fields are set.

    Args:
        monkeypatch: pytest's monkeypatch fixture.
        exclude: An optional field name (e.g. ``"TENANT_ID"``) to leave unset,
            for scenarios testing exactly one missing/invalid field.

    """
    for field_name, value in MICROSOFT_DEFENDER_O365_VALID_REQUIRED_ENV.items():
        if field_name == exclude:
            continue
        _given_microsoft_defender_o365_env_var_set(monkeypatch, field_name, value)


def _when_microsoft_defender_o365_config_is_instantiated(
    module: ModuleType,
) -> tuple[object | None, Exception | None]:
    """When DefenderO365Config is instantiated.

    Args:
        module: The ``src.models.settings.source_configs`` module under test.

    Returns:
        A ``(config, error)`` tuple: the instantiated config and ``None`` on success,
        or ``None`` and the raised exception on failure.

    """
    try:
        return module._ConfigLoaderSource(), None
    except Exception as err:  # pylint: disable=broad-except
        return None, err


def _then_microsoft_defender_o365_no_validation_error_raised(
    error: Exception | None,
) -> None:
    """Then no ValidationError is raised.

    Args:
        error: The error captured by
            ``_when_microsoft_defender_o365_config_is_instantiated``.

    """
    assert error is None, f"Unexpected error raised: {error!r}"


def _then_microsoft_defender_o365_validation_error_is_raised(
    error: Exception | None,
) -> None:
    """Then a ValidationError is raised.

    Args:
        error: The error captured by
            ``_when_microsoft_defender_o365_config_is_instantiated``.

    """
    from pydantic import ValidationError

    assert isinstance(
        error, ValidationError
    ), f"Expected a ValidationError, got: {error!r}"


def _then_microsoft_defender_o365_error_references_field(
    error: "ValidationError", field_name: str  # noqa: F821
) -> None:
    """Then the error references the "<field>" field.

    Args:
        error: The ``pydantic.ValidationError`` captured by
            ``_when_microsoft_defender_o365_config_is_instantiated``.
        field_name: The expected field name referenced by (at least) one of the
            error's ``loc`` tuples.

    """
    locations = [".".join(str(part) for part in e["loc"]) for e in error.errors()]
    assert any(
        field_name in loc for loc in locations
    ), f"Expected an error referencing '{field_name}', got locations: {locations}"


def _then_microsoft_defender_o365_error_references_one_of_fields(
    error: "ValidationError", field_names: list[str]  # noqa: F821
) -> None:
    """Then the error references "<field_a>" or "<field_b>".

    Args:
        error: The ``pydantic.ValidationError`` captured by
            ``_when_microsoft_defender_o365_config_is_instantiated``.
        field_names: The set of field names, at least one of which must be
            referenced by the error's ``loc`` tuples.

    """
    locations = [".".join(str(part) for part in e["loc"]) for e in error.errors()]
    assert any(
        any(field_name in loc for loc in locations) for field_name in field_names
    ), f"Expected an error referencing one of {field_names}, got locations: {locations}"
