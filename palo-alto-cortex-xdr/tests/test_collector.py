import uuid
from unittest.mock import patch

from pyoaev.apis import DetectionExpectation
from src.collector import Collector
from src.models.alert import Incident
from tests.factories import (
    DetectionExpectationFactory,
    IncidentFactory,
    PreventionExpectationFactory,
)


def get_matching_items(
    expectations: list[DetectionExpectation], alerts: Incident
) -> tuple[DetectionExpectation, Incident] | tuple[None, None]:
    """Get the matching expectation for the given alerts."""
    for expectation in expectations:
        for signature in expectation.inject_expectation_signatures:
            if signature.value in alerts.file_artifacts.data[0].file_name:
                return expectation, alerts
    return None, None


def test_collector(expectations, alerts, mock_oaev_api) -> None:
    """Scenario: Start the collector within normal conditions."""
    collector = Collector()
    collector.api = mock_oaev_api
    collector._setup()

    collector._process_callback()

    matching_expectation, matching_alert = get_matching_items(expectations, alerts)

    assert (
        matching_expectation is not None and matching_alert is not None
    ), "No matching expectation found for the alerts"

    # Verify that the API was called for expectations update
    mock_oaev_api.inject_expectation.bulk_update.assert_called_once()
    bulk_expectation = mock_oaev_api.inject_expectation.bulk_update.call_args[1][
        "inject_expectation_input_by_id"
    ]

    assert str(matching_expectation.inject_expectation_id) in bulk_expectation
    assert (
        bulk_expectation[str(matching_expectation.inject_expectation_id)].get(
            "is_success"
        )
        is True
    )

    # Verify that the API was called for traces creation
    mock_oaev_api.inject_expectation_trace.bulk_create.assert_called_once()
    expectation_traces = mock_oaev_api.inject_expectation_trace.bulk_create.call_args[
        1
    ]["payload"]["expectation_traces"]

    assert len(expectation_traces) > 0, "No expectation traces were submitted"
    assert expectation_traces[0]["inject_expectation_trace_expectation"] == str(
        matching_expectation.inject_expectation_id
    )
    assert (
        expectation_traces[0]["inject_expectation_trace_alert_link"]
        == f"https://palo-alto.fake/alerts/{matching_alert.alerts.data[0].alert_id}/{matching_alert.alerts.data[0].case_id}"
    )


def test_collector_no_expectations(alerts, mock_oaev_api) -> None:
    """Scenario: Start the collector when there are no expectations."""
    collector = Collector()
    collector.api = mock_oaev_api
    collector._setup()

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = []
    collector._process_callback()

    # Verify that the API was NOT called for expectations update (or called with empty dict)
    if mock_oaev_api.inject_expectation.bulk_update.called:
        bulk_expectation = mock_oaev_api.inject_expectation.bulk_update.call_args[1][
            "inject_expectation_input_by_id"
        ]
        assert len(bulk_expectation) == 0
    else:
        assert True


def test_detection_expectation_with_detected_alert(mock_oaev_api) -> None:
    """Scenario: DetectionExpectation should succeed when alert has 'Detected' in action_pretty."""
    collector = Collector()
    collector.api = mock_oaev_api
    collector._setup()

    execution_uuid = str(uuid.uuid4())

    class FakeAPIClient:
        @staticmethod
        def update(self, *args, **kwargs):
            return True

    # Create a detection expectation
    expectation = DetectionExpectationFactory.create(api_client=FakeAPIClient())
    expectation.inject_expectation_signatures[1].value = (
        f"oaev-implant-{execution_uuid}"
    )

    # Create an alert with "Detected" in action_pretty
    incident = IncidentFactory()
    incident.file_artifacts.data[0].file_name = f"oaev-implant-{execution_uuid}.exe"
    incident.alerts.data[0].action_pretty = "Detected (Reported)"

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_incident_extra_data",
        return_value=incident,
    ):
        collector._process_callback()

    # Assert the expectation was marked as successful
    mock_oaev_api.inject_expectation.bulk_update.assert_called_once()
    bulk_expectation = mock_oaev_api.inject_expectation.bulk_update.call_args[1][
        "inject_expectation_input_by_id"
    ]
    assert str(expectation.inject_expectation_id) in bulk_expectation
    assert (
        bulk_expectation[str(expectation.inject_expectation_id)].get("is_success")
        is True
    )

    # Assert traces were created
    mock_oaev_api.inject_expectation_trace.bulk_create.assert_called_once()
    expectation_traces = mock_oaev_api.inject_expectation_trace.bulk_create.call_args[
        1
    ]["payload"]["expectation_traces"]
    assert len(expectation_traces) > 0, "No expectation traces were submitted"
    assert expectation_traces[0]["inject_expectation_trace_expectation"] == str(
        expectation.inject_expectation_id
    )


def test_detection_expectation_with_prevented_alert(mock_oaev_api) -> None:
    """Scenario: DetectionExpectation should fail when alert has 'Prevented' instead of 'Detected'."""
    collector = Collector()
    collector.api = mock_oaev_api
    collector._setup()

    execution_uuid = str(uuid.uuid4())

    class FakeAPIClient:
        @staticmethod
        def update(self, *args, **kwargs):
            return True

    # Create a detection expectation
    expectation = DetectionExpectationFactory.create(api_client=FakeAPIClient())
    expectation.inject_expectation_signatures[1].value = (
        f"oaev-implant-{execution_uuid}"
    )

    # Create an alert with "Prevented" (not "Detected")
    incident = IncidentFactory()
    incident.file_artifacts.data[0].file_name = f"oaev-implant-{execution_uuid}.exe"
    incident.alerts.data[0].action_pretty = "Prevented (Blocked)"
    incident.alerts.data = [incident.alerts.data[0]]

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_incident_extra_data",
        return_value=incident,
    ):
        collector._process_callback()

    # Assert the expectation was marked as failed
    mock_oaev_api.inject_expectation.bulk_update.assert_called_once()
    bulk_expectation = mock_oaev_api.inject_expectation.bulk_update.call_args[1][
        "inject_expectation_input_by_id"
    ]
    assert str(expectation.inject_expectation_id) in bulk_expectation
    assert (
        bulk_expectation[str(expectation.inject_expectation_id)].get("is_success")
        is False
    )


def test_prevention_expectation_with_prevented_alert(mock_oaev_api) -> None:
    """Scenario: PreventionExpectation should succeed when alert has 'Prevented' in action_pretty."""
    collector = Collector()
    collector.api = mock_oaev_api
    collector._setup()

    execution_uuid = str(uuid.uuid4())

    class FakeAPIClient:
        @staticmethod
        def update(self, *args, **kwargs):
            return True

    # Create a prevention expectation
    expectation = PreventionExpectationFactory.create(api_client=FakeAPIClient())
    expectation.inject_expectation_signatures[1].value = (
        f"oaev-implant-{execution_uuid}"
    )

    # Create an alert with "Prevented" in action_pretty
    incident = IncidentFactory()
    incident.file_artifacts.data[0].file_name = f"oaev-implant-{execution_uuid}.exe"
    incident.alerts.data[0].action_pretty = "Prevented (Blocked)"

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_incident_extra_data",
        return_value=incident,
    ):
        collector._process_callback()

    # Assert the expectation was marked as successful
    mock_oaev_api.inject_expectation.bulk_update.assert_called_once()
    bulk_expectation = mock_oaev_api.inject_expectation.bulk_update.call_args[1][
        "inject_expectation_input_by_id"
    ]
    assert str(expectation.inject_expectation_id) in bulk_expectation
    assert (
        bulk_expectation[str(expectation.inject_expectation_id)].get("is_success")
        is True
    )

    # Assert traces were created
    mock_oaev_api.inject_expectation_trace.bulk_create.assert_called_once()
    expectation_traces = mock_oaev_api.inject_expectation_trace.bulk_create.call_args[
        1
    ]["payload"]["expectation_traces"]
    assert len(expectation_traces) > 0, "No expectation traces were submitted"
    assert expectation_traces[0]["inject_expectation_trace_expectation"] == str(
        expectation.inject_expectation_id
    )


def test_prevention_expectation_with_detected_alert(mock_oaev_api) -> None:
    """Scenario: PreventionExpectation should fail when alert has 'Detected' instead of 'Prevented'."""
    collector = Collector()
    collector.api = mock_oaev_api
    collector._setup()

    execution_uuid = str(uuid.uuid4())

    class FakeAPIClient:
        @staticmethod
        def update(self, *args, **kwargs):
            return True

    # Create a prevention expectation
    expectation = PreventionExpectationFactory.create(api_client=FakeAPIClient())
    expectation.inject_expectation_signatures[1].value = (
        f"oaev-implant-{execution_uuid}"
    )

    # Create an alert with "Detected" (not "Prevented")
    incident = IncidentFactory()
    incident.file_artifacts.data[0].file_name = f"oaev-implant-{execution_uuid}.exe"
    incident.alerts.data[0].action_pretty = "Detected (Blocked)"
    incident.alerts.data = [incident.alerts.data[0]]

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_incident_extra_data",
        return_value=incident,
    ):
        collector._process_callback()

    # Assert the expectation was marked as failed
    mock_oaev_api.inject_expectation.bulk_update.assert_called_once()
    bulk_expectation = mock_oaev_api.inject_expectation.bulk_update.call_args[1][
        "inject_expectation_input_by_id"
    ]
    assert str(expectation.inject_expectation_id) in bulk_expectation
    assert (
        bulk_expectation[str(expectation.inject_expectation_id)].get("is_success")
        is False
    )


def test_detection_expectation_with_non_matching_signature(mock_oaev_api) -> None:
    """Scenario: DetectionExpectation should fail when alert has different UUID."""
    collector = Collector()
    collector.api = mock_oaev_api
    collector._setup()

    execution_uuid = str(uuid.uuid4())
    different_uuid = str(uuid.uuid4())

    class FakeAPIClient:
        @staticmethod
        def update(self, *args, **kwargs):
            return True

    # Create a detection expectation with one UUID
    expectation = DetectionExpectationFactory.create(api_client=FakeAPIClient())
    expectation.inject_expectation_signatures[1].value = (
        f"oaev-implant-{execution_uuid}"
    )

    # Create an alert with a different UUID
    incident = IncidentFactory()
    incident.file_artifacts.data[0].file_name = f"oaev-implant-{different_uuid}.exe"

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_incident_extra_data",
        return_value=incident,
    ):
        collector._process_callback()

    # Assert the expectation was marked as failed (no match)
    mock_oaev_api.inject_expectation.bulk_update.assert_called_once()
    bulk_expectation = mock_oaev_api.inject_expectation.bulk_update.call_args[1][
        "inject_expectation_input_by_id"
    ]
    assert str(expectation.inject_expectation_id) in bulk_expectation
    assert (
        bulk_expectation[str(expectation.inject_expectation_id)].get("is_success")
        is False
    )
