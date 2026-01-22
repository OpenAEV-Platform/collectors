from typing import Any
from unittest.mock import patch

from pyoaev.apis import DetectionExpectation
from src.collector import Collector
from src.models.alert import Alert


def get_matching_items(
    expectations: list[DetectionExpectation], alerts: list[Alert]
) -> tuple[DetectionExpectation, Alert] | tuple[None, None]:
    """Get the matching expectation for the given alerts."""
    for alert in alerts:
        for expectation in expectations:
            for signature in expectation.inject_expectation_signatures:
                if (
                    alert.actor_process_command_line
                    and signature.value in alert.actor_process_command_line
                ):
                    return expectation, alert
    return None, None


def test_collector(expectations, alerts) -> None:
    """Scenario: Start the collector within normal conditions."""
    collector = Collector()
    collector._setup()

    bulk_expectation = {}
    expectation_traces = []

    def capture_sent_bundle(inject_expectation_input_by_id: dict[str, dict[str, Any]]):
        nonlocal bulk_expectation
        bulk_expectation = inject_expectation_input_by_id

    def capture_traces(payload: dict[str, list[Any]]):
        nonlocal expectation_traces
        expectation_traces = payload.get("expectation_traces", [])

    collector.expectation_manager.oaev_api.inject_expectation.bulk_update = (
        capture_sent_bundle
    )
    collector.expectation_manager.oaev_api.inject_expectation_trace.bulk_create = (
        capture_traces
    )
    collector._process_callback()

    matching_expectation, matching_alert = get_matching_items(expectations, alerts)

    assert (
        matching_expectation is not None and matching_alert is not None
    ), "No matching expectation found for the alerts"
    assert str(matching_expectation.inject_expectation_id) in bulk_expectation
    assert (
        bulk_expectation[str(matching_expectation.inject_expectation_id)].get(
            "is_success"
        )
        is True
    )

    assert len(expectation_traces) > 0, "No expectation traces were submitted"
    assert expectation_traces[0]["inject_expectation_trace_expectation"] == str(
        matching_expectation.inject_expectation_id
    )
    assert (
        expectation_traces[0]["inject_expectation_trace_alert_link"]
        == f"https://palo-alto.fake/alerts/{matching_alert.alert_id}/{matching_alert.case_id}"
    )


def test_collector_no_alerts(expectations) -> None:
    """Scenario: Start the collector when there is no alerts."""
    collector = Collector()
    collector._setup()

    bulk_expectation = {}

    def capture_sent_bundle(inject_expectation_input_by_id: dict[str, dict[str, Any]]):
        nonlocal bulk_expectation
        bulk_expectation = inject_expectation_input_by_id

    collector.expectation_manager.oaev_api.inject_expectation.bulk_update = (
        capture_sent_bundle
    )

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        return_value=[],
    ):
        collector._process_callback()

    for expectation in expectations:
        assert str(expectation.inject_expectation_id) in bulk_expectation
        assert (
            bulk_expectation[str(expectation.inject_expectation_id)].get("is_success")
            is False
        )


def test_collector_no_expectations(alerts) -> None:
    """Scenario: Start the collector when there is no expectations."""
    collector = Collector()
    collector._setup()

    processed_count = 0

    def capture_sent_bundle(inject_expectation_input_by_id: dict[str, dict[str, Any]]):
        nonlocal processed_count
        processed_count = len(inject_expectation_input_by_id)

    collector.expectation_manager.oaev_api.inject_expectation.bulk_update = (
        capture_sent_bundle
    )

    with patch(
        "pyoaev.apis.inject_expectation.InjectExpectationManager.expectations_models_for_source",
        return_value=[],
    ):
        collector._process_callback()

    assert processed_count == 0
