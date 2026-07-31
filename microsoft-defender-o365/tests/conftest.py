"""Shared pytest fixtures for the Defender O365 collector BDD-style tests.

These fixtures are designed to be reused across every tests/features and
tests/constraints scenario module, following the Given/When/Then helper
convention described in the project's CONTRIBUTING.md.
"""

from __future__ import annotations

from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest
from polyfactory.factories.pydantic_factory import ModelFactory
from pydantic import BaseModel
from pyoaev.apis.inject_expectation.model import DetectionExpectation
from pyoaev.client import OpenAEV

if TYPE_CHECKING:
    from src.collector.engines.basic import BasicCollectorEngine
    from src.collector.models.source import Source
    from src.collector.protocols.source_handler import SourceHandlerProtocol
from pyoaev.apis.inject_expectation.model.expectation import (
    DetectionExpectation,
    ExpectationSignature,
    PreventionExpectation,
)


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
        field_name: The field's env var suffix (e.g. ``"CLIENT_CERT_DATA"``), appended
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


def _given_microsoft_defender_o365_source_declared() -> Source:
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
    stub_return_get_source_data: list[object],
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


def _given_microsoft_defender_o365_collector_engine(
    source: Source,
    source_handler: SourceHandlerProtocol,
    oaev_api: OpenAEV,
) -> BasicCollectorEngine:
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
    )
    engine.configure_engine(config=MagicMock())
    return engine


def _when_microsoft_defender_o365_engine_cycle_triggered(
    engine: BasicCollectorEngine,
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
# Chunk6 (#501) - SourceConfig fixture for contract compliance tests
# --------


@pytest.fixture
def source_config_fixture() -> "object":
    """Input contract fixture: a valid SourceConfig for DataFetcherProtocol tests.

    Builds a minimal _ConfigLoaderSource with the required authentication fields.
    The autouse dotenv isolation fixture ensures no local .env leaks in.
    """
    from src.models.settings.source_configs import _ConfigLoaderSource

    config = _ConfigLoaderSource(
        tenant_id="test-tenant-id",
        client_id="test-client-id",
        client_secret="test-client-secret",
    )
    return config


# --------
# Chunk6 (#501) - Data fetcher GWT helpers for behavioural tests
# --------


def _given_microsoft_defender_o365_single_page_response(
    mock_session, alert_count: int = 3
) -> None:
    """Given the API returns a single page of <N> alerts.

    Args:
        mock_session: The mocked requests.Session object.
        alert_count: Number of alerts to return (default 3).
    """
    alerts = [
        {
            "id": f"ALT-{i:03d}",
            "title": f"Phishing email detected {i}",
            "status": "new",
            "severity": "high",
            "serviceSource": "microsoftDefenderForOffice365",
            "createdDateTime": "2026-07-05T14:00:00Z",
        }
        for i in range(1, alert_count + 1)
    ]
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"value": alerts}
    mock_session.get.return_value = mock_response


def _given_microsoft_defender_o365_multi_page_response(
    mock_session, page_sizes: list[int] = [2, 3]
) -> None:
    """Given the API returns multiple pages of alerts.

    Args:
        mock_session: The mocked requests.Session object.
        page_sizes: List of alert counts per page.
    """
    responses = []
    alert_id = 1
    for idx, size in enumerate(page_sizes):
        alerts = [
            {
                "id": f"ALT-{alert_id:03d}",
                "title": f"Alert {alert_id}",
                "status": "new",
                "severity": "high",
                "serviceSource": "microsoftDefenderForOffice365",
                "createdDateTime": "2026-07-05T14:00:00Z",
            }
            for _ in range(size)
        ]
        mock_response = MagicMock()
        mock_response.status_code = 200
        if idx < len(page_sizes) - 1:
            mock_response.json.return_value = {
                "value": alerts,
                "@odata.nextLink": f"https://graph.microsoft.com/v1.0/security/alerts_v2?$skiptoken=page{idx+1}",
            }
        else:
            mock_response.json.return_value = {"value": alerts}
        responses.append(mock_response)
        alert_id += size
    mock_session.get.side_effect = responses


def _given_microsoft_defender_o365_mixed_evidence_response(
    mock_session,
) -> None:
    """Given the API returns alerts with mixed evidence types.

    Args:
        mock_session: The mocked requests.Session object.
    """
    alert = {
        "id": "ALT-001",
        "title": "Phishing email detected",
        "status": "new",
        "severity": "high",
        "serviceSource": "microsoftDefenderForOffice365",
        "createdDateTime": "2026-07-05T14:00:00Z",
        "evidence": [
            {
                "@odata.type": "#microsoft.graph.security.analyzedMessageEvidence",
                "subject": "Invoice",
                "p1Sender": {"emailAddress": "bad@evil.com"},
            },
            {
                "@odata.type": "#microsoft.graph.security.urlEvidence",
                "url": "https://example.com",
            },
        ],
    }
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"value": [alert]}
    mock_session.get.return_value = mock_response


def _given_microsoft_defender_o365_empty_response(mock_session) -> None:
    """Given the API returns an empty value array.

    Args:
        mock_session: The mocked requests.Session object.
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"value": []}
    mock_session.get.return_value = mock_response


def _given_microsoft_defender_o365_rate_limited_response(
    mock_session,
) -> None:
    """Given the API returns a 429 rate limit response followed by success.

    Args:
        mock_session: The mocked requests.Session object.
    """
    response_429 = MagicMock()
    response_429.status_code = 429
    response_429.headers = {"Retry-After": "1"}
    response_429.json.return_value = {"value": []}

    response_ok = MagicMock()
    response_ok.status_code = 200
    response_ok.json.return_value = {
        "value": [
            {
                "id": "ALT-001",
                "title": "Alert",
                "status": "new",
                "severity": "high",
                "serviceSource": "microsoftDefenderForOffice365",
                "createdDateTime": "2026-07-05T14:00:00Z",
            }
        ]
    }
    mock_session.get.side_effect = [response_429, response_ok]


def _given_microsoft_defender_o365_token_expired_response(
    mock_session,
) -> None:
    """Given the API returns a 401 response followed by success.

    Args:
        mock_session: The mocked requests.Session object.
    """
    response_401 = MagicMock()
    response_401.status_code = 401
    response_401.json.return_value = {"value": []}

    response_ok = MagicMock()
    response_ok.status_code = 200
    response_ok.json.return_value = {
        "value": [
            {
                "id": "ALT-001",
                "title": "Alert",
                "status": "new",
                "severity": "high",
                "serviceSource": "microsoftDefenderForOffice365",
                "createdDateTime": "2026-07-05T14:00:00Z",
            }
        ]
    }
    mock_session.get.side_effect = [response_401, response_ok]


def _when_microsoft_defender_o365_fetcher_fetches_data(
    config, mock_session, mock_auth
) -> list:
    """When the data fetcher retrieves alerts.

    Patches MSAL authority and session before construction to prevent
    live OIDC tenant discovery.

    Args:
        config: The source configuration object.
        mock_session: The mocked requests.Session.
        mock_auth: The mocked MSGraphAuthClient.

    Returns:
        The list of MicrosoftDefenderO365SourceData objects.
    """
    from unittest.mock import patch

    from src.source.defender_o365_data_fetcher import DefenderO365DataFetcher

    with (
        patch(
            "src.source.defender_o365_data_fetcher.MSGraphAuthClient",
            return_value=mock_auth,
        ),
        patch(
            "src.source.defender_o365_data_fetcher.Session", return_value=mock_session
        ),
    ):
        fetcher = DefenderO365DataFetcher(config)
        return fetcher.fetch_data()


def _then_result_is_list_of_source_data(result) -> None:
    """Then the fetcher returns a list of source data objects.

    Args:
        result: The fetch result to check.
    """
    assert isinstance(result, list)


def _then_each_result_has_raw_alert(result) -> None:
    """Then each source data object contains the raw alert data.

    Args:
        result: The fetch result to check.
    """
    for item in result:
        assert hasattr(item, "alert")


def _then_result_count_equals(result, expected_count: int) -> None:
    """Then the result count equals the expected count.

    Args:
        result: The fetch result to check.
        expected_count: The expected number of results.
    """
    assert len(result) == expected_count


def _then_result_is_empty(result) -> None:
    """Then the fetcher returns an empty list.

    Args:
        result: The fetch result to check.
    """
    assert result == []


def _then_only_analyzed_message_evidence_preserved(result) -> None:
    """Then only analyzedMessageEvidence items are preserved.

    Checks that each alert is a compact dict with id, status,
    createdDateTime, and compacted evidence (urls, p1/p2 sender info,
    recipient email) rather than the full Graph payload.

    Args:
        result: The fetch result to check.
    """
    EXPECTED_ALERT_KEYS = {"id", "status", "createdDateTime", "evidence"}
    EXPECTED_EVIDENCE_KEYS = {
        "urls",
        "p1_sender_email",
        "p1_sender_display_name",
        "p2_sender_email",
        "p2_sender_display_name",
        "recipient_email_address",
    }
    for item in result:
        if item.alert:
            assert EXPECTED_ALERT_KEYS.issubset(item.alert.keys())
            for ev in item.alert["evidence"]:
                assert isinstance(ev, dict)
                assert EXPECTED_EVIDENCE_KEYS.issubset(ev.keys())


# --------
# Source Data to OAEVData mapping - GWT helpers
# --------


def _given_compacted_alert_with_full_evidence(
    alert_id: str,
    p1_sender: str,
    p2_sender: str,
    recipient: str,
    url: str,
) -> dict:
    """Given a compacted alert with full evidence.

    Args:
        alert_id: The alert identifier.
        p1_sender: The P1 sender email address.
        p2_sender: The P2 sender email address.
        recipient: The recipient email address.
        url: The URL found in evidence.

    Returns:
        A compacted alert dict matching the structure produced by
        DefenderO365Alert.filter_evidence().
    """
    return {
        "id": alert_id,
        "status": "new",
        "alertWebUrl": "https://security.microsoft.com/alerts/" + alert_id,
        "createdDateTime": "2026-07-01T08:00:00+00:00",
        "evidence": [
            {
                "urls": [url],
                "p1_sender_email": p1_sender,
                "p1_sender_display_name": None,
                "p2_sender_email": p2_sender,
                "p2_sender_display_name": None,
                "recipient_email_address": recipient,
            }
        ],
    }


def _given_compacted_alert_with_duplicate_sender() -> dict:
    """Given a compacted alert with two evidence items sharing the same sender.

    Returns:
        A compacted alert dict with duplicate p1_sender_email values.
    """
    return {
        "id": "ALT-002",
        "status": "new",
        "alertWebUrl": "https://security.microsoft.com/alerts/ALT-002",
        "createdDateTime": "2026-07-01T09:00:00+00:00",
        "evidence": [
            {
                "urls": [],
                "p1_sender_email": "bad@evil.com",
                "p1_sender_display_name": None,
                "p2_sender_email": None,
                "p2_sender_display_name": None,
                "recipient_email_address": "victim@corp.com",
            },
            {
                "urls": [],
                "p1_sender_email": "bad@evil.com",
                "p1_sender_display_name": None,
                "p2_sender_email": None,
                "p2_sender_display_name": None,
                "recipient_email_address": "victim@corp.com",
            },
        ],
    }


def _given_compacted_alert_with_empty_evidence() -> dict:
    """Given a compacted alert with an empty evidence list.

    Returns:
        A compacted alert dict with no evidence items.
    """
    return {
        "id": "ALT-003",
        "status": "active",
        "alertWebUrl": "https://security.microsoft.com/alerts/ALT-003",
        "createdDateTime": "2026-07-01T10:00:00+00:00",
        "evidence": [],
    }


def _given_compacted_alert_with_merged_evidence() -> dict:
    """Given a compacted alert with two distinct evidence items.

    Returns:
        A compacted alert dict whose evidence list must be merged
        across items by to_oaev_data.
    """
    return {
        "id": "ALT-004",
        "status": "new",
        "alertWebUrl": "https://security.microsoft.com/alerts/ALT-004",
        "createdDateTime": "2026-07-01T11:00:00+00:00",
        "evidence": [
            {
                "urls": ["https://url1.example.com/"],
                "p1_sender_email": "sender1@evil.com",
                "p1_sender_display_name": None,
                "p2_sender_email": None,
                "p2_sender_display_name": None,
                "recipient_email_address": "victim1@corp.com",
            },
            {
                "urls": ["https://url2.example.com/"],
                "p1_sender_email": "sender2@evil.com",
                "p1_sender_display_name": None,
                "p2_sender_email": None,
                "p2_sender_display_name": None,
                "recipient_email_address": "victim2@corp.com",
            },
        ],
    }


def _when_source_data_to_oaev_data_is_called(alert_dict: dict):
    """When to_oaev_data is called.

    Instantiates MicrosoftDefenderO365SourceData with the provided
    compacted alert dict and invokes to_oaev_data().

    Args:
        alert_dict: A compacted alert dict as produced by
            DefenderO365Alert.filter_evidence().

    Returns:
        The OAEVData instance returned by to_oaev_data().
    """
    from src.source.source_data import MicrosoftDefenderO365SourceData

    source_data = MicrosoftDefenderO365SourceData(alert=alert_dict)
    return source_data.to_oaev_data()


def _then_oaev_data_source_email_list(oaev_data, expected: list[str]) -> None:
    """Then OAEVData[SIG_TYPE_SOURCE_EMAIL] is a list containing the expected emails.

    Args:
        oaev_data: The OAEVData instance under assertion.
        expected: The expected list of sender email addresses.
    """
    from pyoaev.signatures.types import SignatureTypes

    actual = oaev_data.model_dump().get(SignatureTypes.SIG_TYPE_SOURCE_EMAIL.value)
    assert actual == expected, f"Expected {expected}, got {actual}"


def _then_oaev_data_target_email_list(oaev_data, expected: list[str]) -> None:
    """Then OAEVData[SIG_TYPE_TARGET_EMAIL] is a list containing the expected emails.

    Args:
        oaev_data: The OAEVData instance under assertion.
        expected: The expected list of recipient email addresses.
    """
    from pyoaev.signatures.types import SignatureTypes

    actual = oaev_data.model_dump().get(SignatureTypes.SIG_TYPE_TARGET_EMAIL.value)
    assert actual == expected, f"Expected {expected}, got {actual}"


def _then_oaev_data_url_hash_list(oaev_data, expected: list[str]) -> None:
    """Then OAEVData[SIG_TYPE_URL_HASH] is a list containing the expected hash digests.

    Args:
        oaev_data: The OAEVData instance under assertion.
        expected: The expected list of URL hash digests (SHA256, SHA1, MD5).
    """
    from pyoaev.signatures.types import SignatureTypes

    actual = oaev_data.model_dump().get(SignatureTypes.SIG_TYPE_URL_HASH.value)
    assert actual == expected, f"Expected {expected}, got {actual}"


def _then_oaev_data_field_is_empty_string(oaev_data, field: str) -> None:
    """Then OAEVData[field] is an empty string.

    Args:
        oaev_data: The OAEVData instance under assertion.
        field: The signature type field key to check.
    """
    actual = oaev_data.model_dump().get(field)
    assert actual == "", f"Expected empty string for {field}, got {actual!r}"


def _then_oaev_data_field_is_empty_list(oaev_data, field: str) -> None:
    """Then OAEVData[field] is an empty list.

    Args:
        oaev_data: The OAEVData instance under assertion.
        field: The signature type field key to check.
    """
    actual = oaev_data.model_dump().get(field)
    assert actual == [], f"Expected empty list for {field}, got {actual!r}"


def _then_oaev_data_source_email_deduplicated(oaev_data, email: str) -> None:
    """Then OAEVData[SIG_TYPE_SOURCE_EMAIL] contains exactly one entry for the email.

    Args:
        oaev_data: The OAEVData instance under assertion.
        email: The email address that must appear exactly once.
    """
    from pyoaev.signatures.types import SignatureTypes

    actual = oaev_data.model_dump().get(SignatureTypes.SIG_TYPE_SOURCE_EMAIL.value)
    assert actual == [email], f"Expected [{email}], got {actual}"


def _then_oaev_data_contains_hashes_from_both_urls(oaev_data, urls: list[str]) -> None:
    """Then OAEVData[SIG_TYPE_URL_HASH] contains hashes derived from both URLs.

    Verifies that SHA256, SHA1, and MD5 digests for each URL are present
    in the URL hash list.

    Args:
        oaev_data: The OAEVData instance under assertion.
        urls: The list of URLs whose hashes must be present.
    """
    import hashlib

    from pyoaev.signatures.types import SignatureTypes

    actual = oaev_data.model_dump().get(SignatureTypes.SIG_TYPE_URL_HASH.value)
    for url in urls:
        sha256 = hashlib.sha256(url.encode("utf-8")).hexdigest()
        sha1 = hashlib.sha1(url.encode("utf-8")).hexdigest()
        md5 = hashlib.md5(url.encode("utf-8")).hexdigest()
        for digest in (sha256, sha1, md5):
            assert digest in actual, f"Expected {digest} in {actual}"


# --------
# Chunk8 (#505) - Matching integration GWT helpers
# --------

#: Module-level state to control fetcher behaviour across test scenarios
_CHUNK8_STATE: dict[str, object] = {}


def _reset_chunk8_state() -> None:
    """Clear chunk8 test state before each scenario."""
    _CHUNK8_STATE.clear()


@pytest.fixture(autouse=True)
def _chunk8_state_isolation():
    """Ensure chunk8 state is clean before and after each test."""
    _reset_chunk8_state()
    yield
    _reset_chunk8_state()


def _given_detection_expectation_with_supported_sigs(
    exp_id: str = "exp-001",
) -> DetectionExpectation:
    """Given a DetectionExpectation with signatures matching the 5 supported types.

    Args:
        exp_id: The expectation identifier.

    Returns:
        A DetectionExpectation instance with signatures for each supported type.
    """
    import uuid

    from src.source.signatures import SUPPORTED_SIGNATURES

    return DetectionExpectation(
        inject_expectation_id=uuid.uuid4(),
        inject_expectation_signatures=[
            ExpectationSignature(
                type=sig_type,
                value=_sig_test_value_for_type(sig_type),
            )
            for sig_type in SUPPORTED_SIGNATURES
        ],
        api_client=None,
    )


def _given_prevention_expectation_with_supported_sigs() -> PreventionExpectation:
    """Given a PreventionExpectation with signatures matching the 5 supported types.

    Returns:
        A PreventionExpectation instance with signatures for each supported type.
    """
    import uuid

    from src.source.signatures import SUPPORTED_SIGNATURES

    return PreventionExpectation(
        inject_expectation_id=uuid.uuid4(),
        inject_expectation_signatures=[
            ExpectationSignature(
                type=sig_type,
                value=_sig_test_value_for_type(sig_type),
            )
            for sig_type in SUPPORTED_SIGNATURES
        ],
        api_client=None,
    )


def _given_expectation_with_unsupported_sigs() -> DetectionExpectation:
    """Given an expectation with signatures including types NOT in SUPPORTED_SIGNATURES.

    Returns:
        A DetectionExpectation with both supported and unsupported signature types.
    """
    import uuid

    from pyoaev.apis.inject_expectation.model.expectation import (
        DetectionExpectation,
        ExpectationSignature,
    )
    from pyoaev.signatures.types import SignatureTypes
    from src.source.signatures import SUPPORTED_SIGNATURES

    # Add a signature type not in SUPPORTED_SIGNATURES
    all_types = list(SignatureTypes)
    extra_types = [t for t in all_types if t not in SUPPORTED_SIGNATURES][:2]

    sigs = [
        ExpectationSignature(type=sig_type, value=_sig_test_value_for_type(sig_type))
        for sig_type in SUPPORTED_SIGNATURES
    ] + [ExpectationSignature(type=t, value="unsupported-value") for t in extra_types]

    return DetectionExpectation(
        inject_expectation_id=uuid.uuid4(),
        inject_expectation_signatures=sigs,
        api_client=None,
    )


def _given_matching_alert_data(
    prevention: bool = False,
) -> list:
    """Given source data producing OAEVData with matching values and correct detection.

    Builds mock MicrosoftDefenderO365SourceData objects whose to_oaev_data()
    returns values that match the expectation signatures, and whose
    is_detected() / is_prevented() return the correct flag.

    Args:
        prevention: If True, is_prevented() returns True instead of is_detected().

    Returns:
        A list containing one mock source data object.
    """
    from unittest.mock import MagicMock

    from pyoaev.signatures.types import SignatureTypes
    from src.source.signatures import SUPPORTED_SIGNATURES

    mock_sd = MagicMock()
    oaev_data = MagicMock()

    # to_oaev_data returns an OAEVData-like object with matching values
    def to_oaev_data():
        return oaev_data

    mock_sd.to_oaev_data = to_oaev_data

    # Set attribute access to return matching values in the structure
    # expected by OpenAEVDetectionHelper.match_alert_elements
    sig_values = {
        SignatureTypes.SIG_TYPE_SOURCE_EMAIL.value: {
            "type": "simple",
            "data": ["bad@evil.com"],
        },
        SignatureTypes.SIG_TYPE_TARGET_EMAIL.value: {
            "type": "simple",
            "data": ["victim@corp.com"],
        },
        SignatureTypes.SIG_TYPE_URL_HASH.value: {
            "type": "simple",
            "data": ["6e828dac1a6b547942ad393d0e3b5e37e50e974a86c8c61e5b77e6a0c7b7c6d"],
        },
        SignatureTypes.SIG_TYPE_FILE_HASH.value: {
            "type": "simple",
            "data": ["abc123"],
        },
        SignatureTypes.SIG_TYPE_EMAIL_CUSTOM_HEADER.value: {
            "type": "simple",
            "data": ["header-val"],
        },
    }
    oaev_data.model_dump.return_value = sig_values
    for sig_type in SUPPORTED_SIGNATURES:
        setattr(oaev_data, sig_type.value, sig_values[sig_type.value])

    # Detection / prevention flags
    mock_sd.is_detected.return_value = not prevention
    mock_sd.is_prevented.return_value = prevention

    # Trace data serialization
    mock_trace = MagicMock()
    mock_trace.model_dump.return_value = {
        "alert_name": "Test Alert",
        "alert_link": "https://security.microsoft.com/alerts/ALT-001",
        "alert_date": "2026-07-01T08:00:00Z",
    }
    mock_sd.to_traces_data.return_value = mock_trace

    return [mock_sd]


def _given_non_matching_alert_data() -> list:
    """Given source data producing OAEVData with non-matching values.

    Returns:
        A list containing one mock source data object with different values.
    """
    from unittest.mock import MagicMock

    from pyoaev.signatures.types import SignatureTypes
    from src.source.signatures import SUPPORTED_SIGNATURES

    mock_sd = MagicMock()
    oaev_data = MagicMock()

    def to_oaev_data():
        return oaev_data

    mock_sd.to_oaev_data = to_oaev_data

    # Values that won't match expectation signatures
    sig_values = {
        SignatureTypes.SIG_TYPE_SOURCE_EMAIL.value: {
            "type": "simple",
            "data": ["other@evil.com"],
        },
        SignatureTypes.SIG_TYPE_TARGET_EMAIL.value: {
            "type": "simple",
            "data": ["boss@corp.com"],
        },
        SignatureTypes.SIG_TYPE_URL_HASH.value: {
            "type": "simple",
            "data": [
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            ],
        },
        SignatureTypes.SIG_TYPE_FILE_HASH.value: {
            "type": "simple",
            "data": ["xyz789"],
        },
        SignatureTypes.SIG_TYPE_EMAIL_CUSTOM_HEADER.value: {
            "type": "simple",
            "data": ["other-header"],
        },
    }
    oaev_data.model_dump.return_value = sig_values
    for sig_type in SUPPORTED_SIGNATURES:
        setattr(oaev_data, sig_type.value, sig_values[sig_type.value])

    mock_sd.is_detected.return_value = True
    mock_sd.is_prevented.return_value = False

    mock_trace = MagicMock()
    mock_trace.model_dump.return_value = {
        "alert_name": "Test Alert",
        "alert_link": "https://security.microsoft.com/alerts/ALT-002",
        "alert_date": "2026-07-01T09:00:00Z",
    }
    mock_sd.to_traces_data.return_value = mock_trace

    return [mock_sd]


def _given_empty_fetched_data() -> None:
    """Given fetch_data() returns empty list.

    Sets chunk8 state so _when_engine_processes_batch returns [] for data.
    """
    _CHUNK8_STATE["fetch_result"] = []


def _given_fetched_data_error() -> None:
    """Given fetch_data() raises an exception.

    Sets chunk8 state so _when_engine_processes_batch raises on fetch.
    """
    _CHUNK8_STATE["fetch_error"] = RuntimeError("Connection timeout")


def _when_engine_processes_batch(
    expectations: list,
    alert_data: list,
) -> list:
    """When the engine processes the batch.

    Instantiates a minimal BasicCollectorEngine with mocked dependencies
    and calls _process_batch with the provided expectations and alert data.

    Args:
        expectations: List of expectation objects to process.
        alert_data: List of source data objects (mocked).

    Returns:
        List of ExpectationResult objects.
    """
    from pyoaev.helpers import OpenAEVDetectionHelper
    from src.collector.engines.basic import BasicCollectorEngine
    from src.collector.models.source import SourceHandler
    from src.models.settings.source_configs import _ConfigLoaderSource
    from src.source.signatures import SUPPORTED_SIGNATURES

    # Check for error scenario
    if _CHUNK8_STATE.get("fetch_error"):
        data = [
            _CHUNK8_STATE["fetch_error"],
        ]  # trigger error path
    else:
        data = alert_data if alert_data else _CHUNK8_STATE.get("fetch_result", [])

    # Build signature groups for matching
    SourceHandler.get_expectation_signature_groups(
        SUPPORTED_SIGNATURES, expectations[0]
    )

    # Detection helper that matches based on sig groups
    OpenAEVDetectionHelper(
        logger=MagicMock(),
        relevant_signatures_types=SUPPORTED_SIGNATURES,
    )

    # Mock the source handler to inject our data
    mock_handler = MagicMock(spec=SourceHandler)
    mock_handler.config = _ConfigLoaderSource(
        tenant_id="test-tenant-id",
        client_id="test-client-id",
        client_secret="test-secret",
    )

    def get_source_data(fetcher):
        if _CHUNK8_STATE.get("fetch_error"):
            raise _CHUNK8_STATE["fetch_error"]
        return data

    mock_handler.get_source_data = get_source_data
    mock_handler.serialize_as_oaevdata = SourceHandler.serialize_as_oaevdata
    mock_handler.get_expectation_signature_groups = (
        SourceHandler.get_expectation_signature_groups
    )
    mock_handler.match_signature_groups_and_oaevdata = (
        SourceHandler.match_signature_groups_and_oaevdata
    )
    mock_handler.serialize_as_tracedata = SourceHandler.serialize_as_tracedata
    mock_handler.match_expectation_and_sourcedata = (
        SourceHandler.match_expectation_and_sourcedata
    )
    mock_handler.build_fetch_params_hook = SourceHandler.build_fetch_params_hook

    # Build engine with real Source instance
    from src.collector.models.source import Source
    from src.source.defender_o365_data_fetcher import DefenderO365DataFetcher
    from src.source.source_data import MicrosoftDefenderO365SourceData

    # Simple data fetcher class to avoid auth during test
    class MockDataFetcher(DefenderO365DataFetcher):
        def __init__(self, config, fetch_params_hook=None):
            self.config = config
            self._fetch_params_hook = fetch_params_hook

    mock_source = Source(
        data_fetcher_model=MockDataFetcher,
        source_data_model=MicrosoftDefenderO365SourceData,
        signatures=SUPPORTED_SIGNATURES,
    )

    from pyoaev import OpenAEV

    engine = BasicCollectorEngine(
        name="Test Collector",
        collector_id="test-collector-id",
        source=mock_source,
        source_handler=mock_handler,
        oaev_api=MagicMock(spec=OpenAEV),
    )
    engine.configure_engine(MagicMock())

    return engine._process_batch(expectations)


def _when_source_handler_filters_sigs(expectation) -> dict:
    """When SourceHandler.get_expectation_signature_groups filters signatures.

    Args:
        expectation: The expectation object to filter.

    Returns:
        The filtered signature groups dict.
    """
    from src.collector.models.source import SourceHandler
    from src.source.signatures import SUPPORTED_SIGNATURES

    return SourceHandler.get_expectation_signature_groups(
        SUPPORTED_SIGNATURES, expectation
    )


# --------
# Then helpers
# --------


def _then_expectation_result_is_valid_with_traces(result) -> None:
    """Then ExpectationResult.is_valid is True and matched_alerts contains traces.

    Args:
        result: The ExpectationResult to check.
    """
    assert result.is_valid is True, f"Expected is_valid=True, got {result.is_valid}"
    assert (
        len(result.matched_alerts) > 0
    ), f"Expected matched_alerts to be non-empty, got {result.matched_alerts}"


def _then_expectation_result_is_valid_without_traces(result) -> None:
    """Then ExpectationResult.is_valid is True.

    Args:
        result: The ExpectationResult to check.
    """
    assert result.is_valid is True, f"Expected is_valid=True, got {result.is_valid}"


def _then_expectation_result_not_valid_no_traces(result) -> None:
    """Then ExpectationResult.is_valid is False and matched_alerts is empty.

    Args:
        result: The ExpectationResult to check.
    """
    assert result.is_valid is False, f"Expected is_valid=False, got {result.is_valid}"
    assert (
        len(result.matched_alerts) == 0
    ), f"Expected matched_alerts to be empty, got {result.matched_alerts}"


def _then_only_supported_sigs_retained(sig_groups: dict) -> None:
    """Then only signatures matching SUPPORTED_SIGNATURES are retained.

    Args:
        sig_groups: The filtered signature groups dict.
    """
    from src.source.signatures import SUPPORTED_SIGNATURES

    supported_values = {sig.value for sig in SUPPORTED_SIGNATURES}
    for sig_type_key in sig_groups:
        assert (
            sig_type_key in supported_values
        ), f"Unexpected signature type '{sig_type_key}' in groups"


def _then_all_results_invalid(results: list) -> None:
    """Then all ExpectationResult objects have is_valid=False.

    Args:
        results: The list of ExpectationResult objects to check.
    """
    for result in results:
        assert (
            result.is_valid is False
        ), f"Expected is_valid=False for {result.expectation_id}, got {result.is_valid}"


def _then_expectation_result_has_error(result) -> None:
    """Then ExpectationResult has is_valid=False and error_message set.

    Args:
        result: The ExpectationResult to check.
    """
    assert result.is_valid is False, f"Expected is_valid=False, got {result.is_valid}"
    assert (
        result.error_message is not None
    ), f"Expected error_message to be set, got {result.error_message}"


# --------
# Internal helpers
# --------


def _sig_test_value_for_type(sig_type) -> str:
    """Return a test-appropriate value for a signature type.

    Args:
        sig_type: A SignatureTypes enum value.

    Returns:
        A string value suitable for test expectations.
    """
    from pyoaev.signatures.types import SignatureTypes

    VALUES = {
        SignatureTypes.SIG_TYPE_SOURCE_EMAIL: "bad@evil.com",
        SignatureTypes.SIG_TYPE_TARGET_EMAIL: "victim@corp.com",
        SignatureTypes.SIG_TYPE_URL_HASH: "6e828dac1a6b547942ad393d0e3b5e37e50e974a86c8c61e5b77e6a0c7b7c6d",
        SignatureTypes.SIG_TYPE_FILE_HASH: "abc123",
        SignatureTypes.SIG_TYPE_EMAIL_CUSTOM_HEADER: "header-val",
    }
    return VALUES.get(sig_type, "test-value")
