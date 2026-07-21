"""Shared pytest fixtures for the Defender O365 collector BDD-style tests.

These fixtures are designed to be reused across every tests/features and
tests/constraints scenario module, following the Given/When/Then helper
convention described in the project's CONTRIBUTING.md.
"""

from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock

import pytest
from polyfactory.factories.pydantic_factory import ModelFactory
from pydantic import BaseModel
from pyoaev.apis.inject_expectation.model import DetectionExpectation
from pyoaev.client import OpenAEV


@pytest.fixture(autouse=True)
def _isolate_from_local_dotenv_and_yaml_config(monkeypatch):
    """Prevent a developer's local ``.env``/``config.yml`` from leaking into tests.

    ``ConfigLoader.settings_customise_sources`` gives exclusive priority to a
    ``.env`` file, then to ``config.yml``, over environment variables (see
    ``src/models/settings/config_loader.py``). Both files are gitignored,
    developer-local convenience files that don't exist in CI, but when present
    locally they silently short-circuit every env-var-driven scenario in this
    suite. Making ``Path.exists()`` report ``False`` for exactly these two
    collector-root files keeps the suite deterministic regardless of the local
    working copy state, without touching the developer's actual files.
    """
    real_exists = Path.exists

    def fake_exists(self, *args, **kwargs):
        if self.name in (".env", "config.yml"):
            return False
        return real_exists(self, *args, **kwargs)

    monkeypatch.setattr(Path, "exists", fake_exists)
    yield


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
    ``src/collector_main.py``, exposing a ``main()`` function
    wiring a stub ``Source`` into ``BaseCollector``. Importing it is expected to
    fail until that implementation lands, which is the intended "red" state of
    these tests.
    """
    import src.collector_main as module

    return module


# --------
# Chunk2 (#493) - business configuration (source_configs.py) shared helpers
# --------
#
# Chunk2's Done Checklist names a "DefenderO365Config" class, but the target file
# (src/models/settings/source_configs.py) already holds the template's placeholder scaffold
# class `_ConfigLoaderSource(ConfigBaseSettings)`. The resolution is to keep the template's
# class name/structure and replace only its placeholder fields/aliases with the real business
# fields below, rather than introducing a differently-named class. Gherkin `When ... DefenderO365Config
# is instantiated` steps are therefore implemented against `_ConfigLoaderSource`.

MICROSOFT_DEFENDER_O365_ENV_PREFIX = "SOURCE_"

#: Minimal set of env vars that make `_ConfigLoaderSource` instantiate without error.
MICROSOFT_DEFENDER_O365_VALID_REQUIRED_ENV: dict[str, str] = {
    "TENANT_ID": "test-tenant-id",
    "CLIENT_ID": "test-client-id",
    "CLIENT_SECRET": "test-client-secret",
}


@pytest.fixture
def microsoft_defender_o365_source_config_module() -> ModuleType:
    """Import and expose the config loader module wiring the source configuration.

    ``src.models.settings.config_loader.ConfigLoader`` nests
    ``src.models.settings.source_configs._ConfigLoaderSource`` under its ``source``
    field. Instantiating through ``ConfigLoader`` (rather than the source config
    class directly) is what makes pydantic-settings' ``env_nested_delimiter``
    derive the ``SOURCE_*`` env var prefix automatically from the ``source`` field
    name, without needing per-field aliases.
    """
    import src.models.settings.config_loader as module

    return module


def _given_microsoft_defender_o365_env_var_set(
    monkeypatch, field_name: str, value: str
) -> None:
    """Given SOURCE_<FIELD> is set to "<value>".

    Args:
        monkeypatch: pytest's monkeypatch fixture.
        field_name: The field's env var suffix (e.g. ``"TENANT_ID"``), appended to
            ``MICROSOFT_DEFENDER_O365_ENV_PREFIX``.
        value: The value to set the env var to.

    """
    monkeypatch.setenv(f"{MICROSOFT_DEFENDER_O365_ENV_PREFIX}{field_name}", value)


def _given_microsoft_defender_o365_env_var_not_set(
    monkeypatch, field_name: str
) -> None:
    """Given SOURCE_<FIELD> is not set.

    Args:
        monkeypatch: pytest's monkeypatch fixture.
        field_name: The field's env var suffix (e.g. ``"CLIENT_CERT_PATH"``), appended
            to ``MICROSOFT_DEFENDER_O365_ENV_PREFIX``.

    """
    monkeypatch.delenv(
        f"{MICROSOFT_DEFENDER_O365_ENV_PREFIX}{field_name}", raising=False
    )


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
    monkeypatch, module: ModuleType
) -> tuple[object | None, Exception | None]:
    """When DefenderO365Config is instantiated.

    Sets the OpenAEV platform env vars (unrelated to the scenario under test, but
    required by ``ConfigLoader``) before instantiating, then returns the nested
    ``source`` configuration object so scenarios keep asserting on
    ``config.<field>`` directly.

    Args:
        monkeypatch: pytest's monkeypatch fixture.
        module: The ``src.models.settings.config_loader`` module under test.

    Returns:
        A ``(config, error)`` tuple: the instantiated source config and ``None``
        on success, or ``None`` and the raised exception on failure.

    """
    monkeypatch.setenv("OPENAEV_URL", "https://openaev.example.com")
    monkeypatch.setenv("OPENAEV_TOKEN", "test-openaev-token")
    try:
        return module.ConfigLoader().source, None
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


# --------
# Chunk3 (#495) - engine/main-loop wiring shared helpers
# --------


class DetectionExpectationFactory(ModelFactory[DetectionExpectation]):
    """Polyfactory factory generating dynamic DetectionExpectation fixtures.

    ``DetectionExpectation.__init__`` reads a mandatory ``api_client`` kwarg
    that isn't a Pydantic field, so callers must build via
    ``DetectionExpectationFactory.build(api_client=MagicMock())``.
    """

    __model__ = DetectionExpectation


@pytest.fixture
def detection_expectation_factory() -> type[DetectionExpectationFactory]:
    """Expose the polyfactory factory so feature tests can build mock expectations."""
    return DetectionExpectationFactory


def _given_microsoft_defender_o365_source_declared():
    """And Source is declared as Source(data_fetcher_model=DefenderO365DataFetcher, source_data_model=DefenderO365SourceData, signatures=SUPPORTED_SIGNATURES).

    Returns:
        A ``Source`` instance wired with the collector's real data fetcher,
        source data, and signature classes.

    """
    from src.collector.models.source import Source
    from src.source.data_fetcher import MicrosoftDefenderO365DataFetcher
    from src.source.signatures import SUPPORTED_SIGNATURES
    from src.source.source_data import MicrosoftDefenderO365SourceData

    return Source(
        data_fetcher_model=MicrosoftDefenderO365DataFetcher,
        source_data_model=MicrosoftDefenderO365SourceData,
        signatures=SUPPORTED_SIGNATURES,
    )


def _given_microsoft_defender_o365_oaev_api_returns_expectations(
    expectations: list[DetectionExpectation],
) -> MagicMock:
    """And the OpenAEV API returns at least one mock expectation.

    Args:
        expectations: The expectation objects the mocked API should return.

    Returns:
        A ``MagicMock`` satisfying the ``OpenAEV`` client's interface.

    """
    oaev_api = MagicMock(spec=OpenAEV)
    # ``inject_expectation``/``inject_expectation_trace`` are set as instance
    # attributes inside OpenAEV.__init__ (not class attributes), so `spec`
    # doesn't pick them up automatically: attach them explicitly.
    oaev_api.inject_expectation = MagicMock()
    oaev_api.inject_expectation_trace = MagicMock()
    oaev_api.inject_expectation.expectations_models_for_source.return_value = (
        expectations
    )
    return oaev_api


def _given_microsoft_defender_o365_stubbed_source_handler(
    stub_return_get_source_data: list,
    stub_return_match_groups: bool,
    stub_return_match_expectation: tuple[bool, bool],
) -> MagicMock:
    """Given a DefenderO365Collector(BaseCollector) instance with all methods stubbed.

    Builds a ``SourceHandlerProtocol``-compliant mock with each of its six
    methods stubbed to the values provided by the scenario's Examples table.

    Args:
        stub_return_get_source_data: Value returned by ``get_source_data``.
        stub_return_match_groups: Value returned by
            ``match_signature_groups_and_oaevdata``.
        stub_return_match_expectation: Value returned by
            ``match_expectation_and_sourcedata``.

    Returns:
        A ``MagicMock`` satisfying the ``SourceHandlerProtocol`` interface.

    """
    from src.collector.protocols.source_handler import SourceHandlerProtocol

    source_handler = MagicMock(spec=SourceHandlerProtocol)
    source_handler.config = MagicMock()
    source_handler.get_source_data.return_value = stub_return_get_source_data
    source_handler.serialize_as_oaevdata.return_value = MagicMock()
    source_handler.get_expectation_signature_groups.return_value = {}
    source_handler.match_signature_groups_and_oaevdata.return_value = (
        stub_return_match_groups
    )
    source_handler.serialize_as_tracedata.return_value.model_dump.return_value = {
        "alert_name": "Stubbed Alert",
        "alert_link": "http://stub.example.com/alert",
    }
    source_handler.match_expectation_and_sourcedata.return_value = (
        stub_return_match_expectation
    )
    return source_handler


def _given_microsoft_defender_o365_collector_engine(source, source_handler, oaev_api):
    """Given a DefenderO365Collector(BaseCollector) instance with all methods stubbed.

    Wires a real ``BasicCollectorEngine`` (the generic engine started by
    ``BaseCollector``) with the provided ``Source``, ``SourceHandlerProtocol``
    (mock or real instance), and mocked ``OpenAEV`` API client, then
    configures it so ``run_engine`` can be called directly.

    Args:
        source: The ``Source`` instance declaring the data fetcher/source
            data/signatures.
        source_handler: A ``SourceHandlerProtocol``-compliant mock or
            instance.
        oaev_api: A mocked ``OpenAEV`` API client.

    Returns:
        A configured ``BasicCollectorEngine`` instance ready for
        ``run_engine()``.

    """
    from src.collector.engines.basic import BasicCollectorEngine

    engine = BasicCollectorEngine(
        name="Microsoft Defender O365 Collector",
        collector_id="test-collector-id",
        source=source,
        source_handler=source_handler,
        oaev_api=oaev_api,
        batching=False,
    )
    engine.configure_engine(config=MagicMock())
    return engine


def _when_microsoft_defender_o365_engine_cycle_triggered(
    engine,
) -> Exception | None:
    """When one loop iteration is triggered / When one engine cycle is triggered via run_engine().

    Args:
        engine: The ``BasicCollectorEngine`` instance under test.

    Returns:
        ``None`` on success, or the raised exception on failure.

    """
    try:
        engine.run_engine()
        return None
    except Exception as err:  # pylint: disable=broad-except
        return err


def _then_microsoft_defender_o365_no_unhandled_exception_raised(
    error: Exception | None,
) -> None:
    """Then no unhandled exception is raised.

    Args:
        error: The error captured by
            ``_when_microsoft_defender_o365_engine_cycle_triggered``.

    """
    assert error is None, f"Unexpected exception raised: {error!r}"
