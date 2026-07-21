"""Essential tests for the DefenderO365Collector main loop wiring - Gherkin GWT Format."""

import logging
from contextlib import ExitStack
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest
from src.collector.models.source import SourceHandler
from tests.conftest import (
    DetectionExpectationFactory,
    _given_microsoft_defender_o365_collector_engine,
    _given_microsoft_defender_o365_env_var_set,
    _given_microsoft_defender_o365_oaev_api_returns_expectations,
    _given_microsoft_defender_o365_source_declared,
    _given_microsoft_defender_o365_stubbed_source_handler,
    _then_microsoft_defender_o365_no_unhandled_exception_raised,
    _then_microsoft_defender_o365_no_validation_error_raised,
    _when_microsoft_defender_o365_config_is_instantiated,
    _when_microsoft_defender_o365_engine_cycle_triggered,
)

# --------
# Scenarios
# --------


# Scenario Outline: Collector loop completes a full cycle with stubs
@pytest.mark.parametrize(
    "stub_return_get_source_data, stub_return_match_groups, stub_return_match_expectation",
    [
        ([MagicMock(name="mock_alert")], True, (True, False)),
    ],
    ids=[
        "single_stub_alert_matches",
    ],
)
def test_collector_loop_completes_a_full_cycle_with_stubs(
    detection_expectation_factory: type[DetectionExpectationFactory],
    stub_return_get_source_data: list[object],
    stub_return_match_groups: bool,
    stub_return_match_expectation: tuple[bool, bool],
) -> None:
    """Scenario Outline: Collector loop completes a full cycle with stubs"""
    # Given: CHK.1 scaffold is in place, CHK.2 DefenderO365Config is defined,
    # DataFetcher/OpenAEV API/match_signature_groups_and_oaevdata are stubbed,
    # Source is declared, and a DefenderO365Collector(BaseCollector) instance
    # with all methods stubbed is built
    source = _given_microsoft_defender_o365_source_declared()
    expectation = detection_expectation_factory.build(api_client=MagicMock())
    oaev_api = _given_microsoft_defender_o365_oaev_api_returns_expectations(
        [expectation]
    )
    source_handler = _given_microsoft_defender_o365_stubbed_source_handler(
        stub_return_get_source_data,
        stub_return_match_groups,
        stub_return_match_expectation,
    )
    engine = _given_microsoft_defender_o365_collector_engine(
        source, source_handler, oaev_api
    )

    # When: one loop iteration is triggered
    error = _when_microsoft_defender_o365_engine_cycle_triggered(engine)

    # Then: get_source_data, serialize_as_oaevdata, get_expectation_signature_groups,
    # match_signature_groups_and_oaevdata, match_expectation_and_sourcedata and
    # serialize_as_tracedata are each called exactly once, and no unhandled
    # exception is raised
    _then_get_source_data_is_called_exactly_once(source_handler)
    _then_serialize_as_oaevdata_is_called_exactly_once(source_handler)
    _then_get_expectation_signature_groups_is_called_exactly_once(source_handler)
    _then_match_signature_groups_and_oaevdata_is_called_exactly_once(source_handler)
    _then_match_expectation_and_sourcedata_is_called_exactly_once(source_handler)
    _then_serialize_as_tracedata_is_called_exactly_once(source_handler)
    _then_microsoft_defender_o365_no_unhandled_exception_raised(error)


# Scenario Outline: Configuration is loaded correctly via ConfigLoader
@pytest.mark.parametrize(
    "tenant_id, client_id, client_secret",
    [("test-tenant", "test-client", "test-secret")],
    ids=["credential_environment_variables"],
)
def test_configuration_is_loaded_correctly_via_config_loader(
    monkeypatch: pytest.MonkeyPatch,
    microsoft_defender_o365_source_config_module: ModuleType,
    tenant_id: str,
    client_id: str,
    client_secret: str,
) -> None:
    """Scenario Outline: Configuration is loaded correctly via ConfigLoader."""
    # Given: SOURCE_TENANT_ID, SOURCE_CLIENT_ID, and SOURCE_CLIENT_SECRET are set
    _given_microsoft_defender_o365_env_var_set(monkeypatch, "TENANT_ID", tenant_id)
    _given_microsoft_defender_o365_env_var_set(monkeypatch, "CLIENT_ID", client_id)
    _given_microsoft_defender_o365_env_var_set(
        monkeypatch, "CLIENT_SECRET", client_secret
    )

    # When: the collector is instantiated via ConfigLoader
    config, error = _when_microsoft_defender_o365_config_is_instantiated(
        monkeypatch, microsoft_defender_o365_source_config_module
    )

    # Then: DefenderO365Config loads without error and config.tenant_id matches
    _then_microsoft_defender_o365_no_validation_error_raised(error)
    _then_config_tenant_id_equals(config, tenant_id)


# Scenario: Main entry point starts BaseCollector with the declared Source
def test_main_entry_point_starts_base_collector_with_the_declared_source(
    microsoft_defender_o365_collector_module: ModuleType,
) -> None:
    """Scenario: Main entry point starts BaseCollector with the declared Source."""
    # Given: the collector entry point dependencies are stubbed
    stack, mocks = _given_collector_entry_point_dependencies_stubbed(
        microsoft_defender_o365_collector_module
    )

    try:
        # When: the collector main entry point is invoked
        error = _when_collector_main_entry_point_is_invoked(
            microsoft_defender_o365_collector_module
        )
    finally:
        stack.close()

    # Then: Source is declared with the O365 models/signatures, BaseCollector
    # receives that Source, and BaseCollector is started exactly once
    _then_microsoft_defender_o365_no_unhandled_exception_raised(error)
    _then_source_is_declared_with_microsoft_defender_o365_models(mocks)
    _then_base_collector_is_instantiated_with_declared_source(mocks)
    _then_base_collector_is_started_exactly_once(mocks)


# Scenario Outline: Loop emits LOG_PREFIX log messages at each engine step
@pytest.mark.parametrize(
    "expected_log_count",
    [4],
    ids=["four_log_prefix_messages"],
)
def test_loop_emits_log_prefix_log_messages_at_each_engine_step(
    caplog: pytest.LogCaptureFixture,
    detection_expectation_factory: type[DetectionExpectationFactory],
    expected_log_count: int,
) -> None:
    """Scenario Outline: Loop emits LOG_PREFIX log messages at each engine step"""
    # Given: a DefenderO365Collector with a DataFetcher returning at least
    # one mock alert (the real placeholder DataFetcher/SourceHandler already
    # produce stub data), and the OpenAEV API returns at least one mock
    # expectation
    source = _given_microsoft_defender_o365_source_declared()
    expectation = detection_expectation_factory.build(api_client=MagicMock())
    oaev_api = _given_microsoft_defender_o365_oaev_api_returns_expectations(
        [expectation]
    )
    source_handler = _given_real_microsoft_defender_o365_source_handler()
    engine = _given_microsoft_defender_o365_collector_engine(
        source, source_handler, oaev_api
    )

    # When: one engine cycle is triggered via run_engine()
    with caplog.at_level(logging.INFO, logger="src.collector.engines.basic"):
        error = _when_microsoft_defender_o365_engine_cycle_triggered(engine)

    # Then: a log message containing "[BasicCollectorEngine]" together with
    # "Starting processing cycle", "Fetching data providing", "Batch
    # processed" and "Processing cycle completed" at INFO is emitted
    _then_microsoft_defender_o365_no_unhandled_exception_raised(error)
    _then_log_prefix_messages_are_emitted(
        caplog,
        [
            "Starting processing cycle",
            "Fetching data providing",
            "Batch processed",
            "Processing cycle completed",
        ],
        expected_log_count,
    )


# --------
# Given Methods
# --------


def _given_real_microsoft_defender_o365_source_handler() -> SourceHandler:
    """Given a DefenderO365Collector with a DataFetcher returning at least one mock alert.

    Returns:
        A real ``SourceHandler`` instance (no stubbing), since the collector's
        placeholder ``MicrosoftDefenderO365DataFetcher``/``SourceData``
        classes already produce stub alert data end-to-end.

    """
    from src.collector.models.source import SourceHandler

    return SourceHandler(config=MagicMock())


def _given_collector_entry_point_dependencies_stubbed(
    collector: ModuleType,
) -> tuple[ExitStack, dict[str, MagicMock]]:
    """Given the collector entry point dependencies are stubbed.

    Args:
        collector: The ``src.collector_main`` module under test.

    Returns:
        The active patch stack and a mapping of patched symbols to mocks.

    """
    stack = ExitStack()
    mocks = {
        name: stack.enter_context(patch.object(collector, name))
        for name in (
            "MicrosoftDefenderO365DataFetcher",
            "MicrosoftDefenderO365SourceData",
            "SUPPORTED_SIGNATURES",
            "Source",
            "BaseCollector",
        )
    }
    return stack, mocks


# --------
# When Methods
# --------


def _when_collector_main_entry_point_is_invoked(
    collector: ModuleType,
) -> Exception | None:
    """When the collector main entry point is invoked.

    Args:
        collector: The ``src.collector_main`` module under test.

    Returns:
        ``None`` on success, or the raised exception on failure.

    """
    try:
        collector.main()
        return None
    except Exception as err:  # pylint: disable=broad-except
        return err


# --------
# Then Methods
# --------


def _then_get_source_data_is_called_exactly_once(
    source_handler: MagicMock,
) -> None:
    """Then get_source_data is called exactly once.

    Args:
        source_handler: The stubbed source handler used by the engine.

    """
    source_handler.get_source_data.assert_called_once()


def _then_serialize_as_oaevdata_is_called_exactly_once(
    source_handler: MagicMock,
) -> None:
    """Then serialize_as_oaevdata is called exactly once.

    Args:
        source_handler: The stubbed source handler used by the engine.

    """
    source_handler.serialize_as_oaevdata.assert_called_once()


def _then_get_expectation_signature_groups_is_called_exactly_once(
    source_handler: MagicMock,
) -> None:
    """Then get_expectation_signature_groups is called exactly once.

    Args:
        source_handler: The stubbed source handler used by the engine.

    """
    source_handler.get_expectation_signature_groups.assert_called_once()


def _then_match_signature_groups_and_oaevdata_is_called_exactly_once(
    source_handler: MagicMock,
) -> None:
    """Then match_signature_groups_and_oaevdata is called exactly once.

    Args:
        source_handler: The stubbed source handler used by the engine.

    """
    source_handler.match_signature_groups_and_oaevdata.assert_called_once()


def _then_match_expectation_and_sourcedata_is_called_exactly_once(
    source_handler: MagicMock,
) -> None:
    """Then match_expectation_and_sourcedata is called exactly once.

    Args:
        source_handler: The stubbed source handler used by the engine.

    """
    source_handler.match_expectation_and_sourcedata.assert_called_once()


def _then_serialize_as_tracedata_is_called_exactly_once(
    source_handler: MagicMock,
) -> None:
    """Then serialize_as_tracedata is called exactly once.

    Args:
        source_handler: The stubbed source handler used by the engine.

    """
    source_handler.serialize_as_tracedata.assert_called_once()


def _then_config_tenant_id_equals(config: object, tenant_id: str) -> None:
    """Then config.tenant_id equals the configured tenant identifier.

    Args:
        config: The source configuration loaded through ``ConfigLoader``.
        tenant_id: The expected tenant identifier.

    """
    assert getattr(config, "tenant_id") == tenant_id


def _then_source_is_declared_with_microsoft_defender_o365_models(
    mocks: dict[str, MagicMock],
) -> None:
    """Then Source is declared with the Microsoft Defender O365 models and signatures.

    Args:
        mocks: Mapping of patched entry point symbols to mocks.

    """
    mocks["Source"].assert_called_once_with(
        data_fetcher_model=mocks["MicrosoftDefenderO365DataFetcher"],
        source_data_model=mocks["MicrosoftDefenderO365SourceData"],
        signatures=mocks["SUPPORTED_SIGNATURES"],
    )


def _then_base_collector_is_instantiated_with_declared_source(
    mocks: dict[str, MagicMock],
) -> None:
    """Then BaseCollector is instantiated with the declared Source.

    Args:
        mocks: Mapping of patched entry point symbols to mocks.

    """
    mocks["BaseCollector"].assert_called_once_with(
        name="Microsoft Defender O365 Collector",
        source=mocks["Source"].return_value,
    )


def _then_base_collector_is_started_exactly_once(
    mocks: dict[str, MagicMock],
) -> None:
    """Then BaseCollector is started exactly once.

    Args:
        mocks: Mapping of patched entry point symbols to mocks.

    """
    mocks["BaseCollector"].return_value.start.assert_called_once_with()


def _then_log_prefix_messages_are_emitted(
    caplog: pytest.LogCaptureFixture,
    expected_substrings: list[str],
    expected_log_count: int,
) -> None:
    """Then a log message containing "[BasicCollectorEngine]" and "<substring>" at INFO is emitted.

    Args:
        caplog: pytest's ``caplog`` fixture, already scoped via ``at_level``.
        expected_substrings: The substrings each expected to appear together
            with ``"[BasicCollectorEngine]"`` in some INFO-level record.
        expected_log_count: The number of distinct expected log messages
            (matches the Examples table's ``expected_log_count`` column).

    """
    info_messages = [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.INFO
    ]
    assert len(expected_substrings) == expected_log_count
    for substring in expected_substrings:
        assert any(
            "[BasicCollectorEngine]" in message and substring in message
            for message in info_messages
        ), f"Expected a log message containing '[BasicCollectorEngine]' and '{substring}'"
