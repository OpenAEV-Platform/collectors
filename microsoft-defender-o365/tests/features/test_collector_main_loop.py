"""Essential tests for the DefenderO365Collector main loop wiring - Gherkin GWT Format."""

import logging
from unittest.mock import MagicMock

import pytest
from tests.conftest import (
    DetectionExpectationFactory,
    _given_microsoft_defender_o365_collector_engine,
    _given_microsoft_defender_o365_oaev_api_returns_expectations,
    _given_microsoft_defender_o365_source_declared,
    _given_microsoft_defender_o365_stubbed_source_handler,
    _then_microsoft_defender_o365_no_unhandled_exception_raised,
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
    stub_return_get_source_data,
    stub_return_match_groups,
    stub_return_match_expectation,
):
    """Scenario Outline: Collector loop completes a full cycle with stubs"""
    # Given: CHK.1 scaffold is in place, CHK.2 DefenderO365Config is defined,
    # DataFetcher/OpenAEV API/match_signature_groups_and_oaevdata are stubbed,
    # Source is declared, and a DefenderO365Collector(BaseCollector) instance
    # with all methods stubbed is built
    source = _given_microsoft_defender_o365_source_declared()
    expectation = DetectionExpectationFactory.build(api_client=MagicMock())
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
    source_handler.get_source_data.assert_called_once()
    source_handler.serialize_as_oaevdata.assert_called_once()
    source_handler.get_expectation_signature_groups.assert_called_once()
    source_handler.match_signature_groups_and_oaevdata.assert_called_once()
    source_handler.match_expectation_and_sourcedata.assert_called_once()
    source_handler.serialize_as_tracedata.assert_called_once()
    _then_microsoft_defender_o365_no_unhandled_exception_raised(error)


# Scenario Outline: Loop emits LOG_PREFIX log messages at each engine step
@pytest.mark.parametrize(
    "expected_log_count",
    [4],
    ids=["four_log_prefix_messages"],
)
def test_loop_emits_log_prefix_log_messages_at_each_engine_step(
    caplog, expected_log_count
):
    """Scenario Outline: Loop emits LOG_PREFIX log messages at each engine step"""
    # Given: a DefenderO365Collector with a DataFetcher returning at least
    # one mock alert (the real placeholder DataFetcher/SourceHandler already
    # produce stub data), and the OpenAEV API returns at least one mock
    # expectation
    source = _given_microsoft_defender_o365_source_declared()
    expectation = DetectionExpectationFactory.build(api_client=MagicMock())
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


def _given_real_microsoft_defender_o365_source_handler():
    """Given a DefenderO365Collector with a DataFetcher returning at least one mock alert.

    Returns:
        A real ``SourceHandler`` instance (no stubbing), since the collector's
        placeholder ``MicrosoftDefenderO365DataFetcher``/``SourceData``
        classes already produce stub alert data end-to-end.

    """
    from src.collector.models.source import SourceHandler

    return SourceHandler(config=MagicMock())


# --------
# When Methods
# --------


# --------
# Then Methods
# --------


def _then_log_prefix_messages_are_emitted(
    caplog, expected_substrings: list[str], expected_log_count: int
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
