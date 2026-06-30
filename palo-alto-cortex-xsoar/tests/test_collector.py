import uuid
from unittest.mock import patch

from pyoaev.apis import DetectionExpectation
from src.collector import Collector
from src.models.incident import CustomFields, XSOARSearchIncidentsResponse
from src.services.ioc_extractor import IncidentResult, IndicatorResults
from tests.factories import (
    AlertFactory,
    DetectionExpectationFactory,
    IncidentFactory,
    PreventionExpectationFactory,
)


def get_matching_items(
    expectations: list[DetectionExpectation], alert
) -> tuple[DetectionExpectation, object] | tuple[None, None]:
    """Get the matching expectation for the given alert by checking signatures against alert's data."""
    for expectation in expectations:
        for signature in expectation.inject_expectation_signatures:
            if "oaev-implant-" in signature.value:
                return expectation, alert
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


def test_no_expectations(mock_oaev_api) -> None:
    """Scenario: No expectations returned from API."""
    collector = Collector()
    collector.api = mock_oaev_api
    collector._setup()

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = []

    collector._process_callback()

    if mock_oaev_api.inject_expectation.bulk_update.called:
        bulk_expectation = mock_oaev_api.inject_expectation.bulk_update.call_args[1][
            "inject_expectation_input_by_id"
        ]
        assert len(bulk_expectation) == 0
    else:
        assert True


def _create_test_mocks(execution_uuid, action="Detected (Reported)"):
    """Helper to create alert mocks for a given execution_uuid."""
    agent_uuid = str(uuid.uuid4())
    implant_name = f"oaev-implant-{execution_uuid}-agent-{agent_uuid}"

    alert = AlertFactory(
        case_id=42,
        actor_process_command_line=implant_name,
    )

    incident = IncidentFactory(custom_fields=CustomFields(xdralerts=[alert]))

    alerts_response = XSOARSearchIncidentsResponse(total=1, data=[incident])

    incident_result = IncidentResult(
        id=str(incident.id),
        action=[action],
        indicators=IndicatorResults(oaev_implant=[implant_name]),
    )

    return alert, alerts_response, incident_result


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

    alert, alerts_response, incident_result = _create_test_mocks(
        execution_uuid, action="Detected (Reported)"
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXSOARClientAPI.search_incidents",
        return_value=alerts_response,
    ), patch(
        "src.services.alert_fetcher.extract_from_custom_fields",
        return_value=[incident_result],
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


def test_detection_expectation_with_prevented_alert(mock_oaev_api) -> None:
    """Scenario: DetectionExpectation should succeed when alert has 'Prevented' (prevention implies detection)."""
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

    alert, alerts_response, incident_result = _create_test_mocks(
        execution_uuid, action="Prevented (Reported)"
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXSOARClientAPI.search_incidents",
        return_value=alerts_response,
    ), patch(
        "src.services.alert_fetcher.extract_from_custom_fields",
        return_value=[incident_result],
    ):
        collector._process_callback()

    # Assert the expectation was marked as successful (prevented implies detected)
    mock_oaev_api.inject_expectation.bulk_update.assert_called_once()
    bulk_expectation = mock_oaev_api.inject_expectation.bulk_update.call_args[1][
        "inject_expectation_input_by_id"
    ]
    assert str(expectation.inject_expectation_id) in bulk_expectation
    assert (
        bulk_expectation[str(expectation.inject_expectation_id)].get("is_success")
        is True
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

    alert, alerts_response, incident_result = _create_test_mocks(
        execution_uuid, action="Prevented (Reported)"
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXSOARClientAPI.search_incidents",
        return_value=alerts_response,
    ), patch(
        "src.services.alert_fetcher.extract_from_custom_fields",
        return_value=[incident_result],
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

    alert, alerts_response, incident_result = _create_test_mocks(
        execution_uuid, action="Detected (Reported)"
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXSOARClientAPI.search_incidents",
        return_value=alerts_response,
    ), patch(
        "src.services.alert_fetcher.extract_from_custom_fields",
        return_value=[incident_result],
    ):
        collector._process_callback()

    # Assert the expectation was NOT updated (skipped, waiting for correct alert)
    if mock_oaev_api.inject_expectation.bulk_update.called:
        bulk_expectation = mock_oaev_api.inject_expectation.bulk_update.call_args[1][
            "inject_expectation_input_by_id"
        ]
        assert str(expectation.inject_expectation_id) not in bulk_expectation


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
    alert, alerts_response, incident_result = _create_test_mocks(different_uuid)

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXSOARClientAPI.search_incidents",
        return_value=alerts_response,
    ), patch(
        "src.services.alert_fetcher.extract_from_custom_fields",
        return_value=[incident_result],
    ):
        collector._process_callback()

    # Assert the expectation was NOT updated (no match, skipped)
    if mock_oaev_api.inject_expectation.bulk_update.called:
        bulk_expectation = mock_oaev_api.inject_expectation.bulk_update.call_args[1][
            "inject_expectation_input_by_id"
        ]
        assert str(expectation.inject_expectation_id) not in bulk_expectation
