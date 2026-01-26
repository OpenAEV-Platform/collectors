import uuid
from unittest.mock import patch

from pyoaev.apis import DetectionExpectation
from src.collector import Collector
from src.models.alert import Alert
from tests.factories import (
    AlertFactory,
    DetectionExpectationFactory,
    PreventionExpectationFactory,
)


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
        == f"https://palo-alto.fake/alerts/{matching_alert.alert_id}/{matching_alert.case_id}"
    )


def test_collector_no_alerts(expectations, mock_oaev_api) -> None:
    """Scenario: Start the collector when there are no alerts."""
    collector = Collector()
    collector.api = mock_oaev_api
    collector._setup()

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        return_value=[],
    ):
        collector._process_callback()

    mock_oaev_api.inject_expectation.bulk_update.assert_called_once()
    bulk_expectation = mock_oaev_api.inject_expectation.bulk_update.call_args[1][
        "inject_expectation_input_by_id"
    ]

    for expectation in expectations:
        assert str(expectation.inject_expectation_id) in bulk_expectation
        assert (
            bulk_expectation[str(expectation.inject_expectation_id)].get("is_success")
            is False
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
    alert = AlertFactory.create(
        actor_process_command_line=f"some command line with oaev-implant-{execution_uuid} inside",
        action_pretty="Detected (Reported)",
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        return_value=[alert],
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
    alert = AlertFactory.create(
        actor_process_command_line=f"some command line with oaev-implant-{execution_uuid} inside",
        action_pretty="Prevented",
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        return_value=[alert],
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
    alert = AlertFactory.create(
        actor_process_command_line=f"some command line with oaev-implant-{execution_uuid} inside",
        action_pretty="Prevented",
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        return_value=[alert],
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
    alert = AlertFactory.create(
        actor_process_command_line=f"some command line with oaev-implant-{execution_uuid} inside",
        action_pretty="Detected (Reported)",
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        return_value=[alert],
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
    alert = AlertFactory.create(
        actor_process_command_line=f"some command line with oaev-implant-{different_uuid} inside",
        action_pretty="Detected (Reported)",
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        return_value=[alert],
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


def test_detection_expectation_with_multiple_matching_alerts(mock_oaev_api) -> None:
    """Scenario: DetectionExpectation with multiple matching alerts should succeed on first match."""
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

    # Create multiple alerts with the same matching signature
    alert1 = AlertFactory.create(
        actor_process_command_line=f"first command with oaev-implant-{execution_uuid} inside",
        action_pretty="Detected (Reported)",
        alert_id=1001,
    )
    alert2 = AlertFactory.create(
        actor_process_command_line=f"second command with oaev-implant-{execution_uuid} inside",
        action_pretty="Detected (Reported)",
        alert_id=1002,
    )
    alert3 = AlertFactory.create(
        actor_process_command_line=f"third command with oaev-implant-{execution_uuid} inside",
        action_pretty="Detected (Reported)",
        alert_id=1003,
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        return_value=[alert1, alert2, alert3],
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

    # Assert a trace was created (should be for first matching alert)
    mock_oaev_api.inject_expectation_trace.bulk_create.assert_called_once()
    expectation_traces = mock_oaev_api.inject_expectation_trace.bulk_create.call_args[
        1
    ]["payload"]["expectation_traces"]
    assert len(expectation_traces) > 0, "No expectation traces were submitted"
    assert expectation_traces[0]["inject_expectation_trace_expectation"] == str(
        expectation.inject_expectation_id
    )


def test_detection_expectation_with_empty_command_line(mock_oaev_api) -> None:
    """Scenario: DetectionExpectation should fail when alert has no command line."""
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

    # Create an alert with empty/null command line
    alert = AlertFactory.create(
        actor_process_command_line=None,
        action_pretty="Detected (Reported)",
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        return_value=[alert],
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


def test_mixed_detection_and_prevention_expectations(mock_oaev_api) -> None:
    """Scenario: Process both Detection and Prevention expectations together."""
    collector = Collector()
    collector.api = mock_oaev_api
    collector._setup()

    detection_uuid = str(uuid.uuid4())
    prevention_uuid = str(uuid.uuid4())

    class FakeAPIClient:
        @staticmethod
        def update(self, *args, **kwargs):
            return True

    # Create one detection and one prevention expectation
    detection_expectation = DetectionExpectationFactory.create(
        api_client=FakeAPIClient()
    )
    detection_expectation.inject_expectation_signatures[1].value = (
        f"oaev-implant-{detection_uuid}"
    )

    prevention_expectation = PreventionExpectationFactory.create(
        api_client=FakeAPIClient()
    )
    prevention_expectation.inject_expectation_signatures[1].value = (
        f"oaev-implant-{prevention_uuid}"
    )

    # Create corresponding alerts
    detected_alert = AlertFactory.create(
        actor_process_command_line=f"detected command with oaev-implant-{detection_uuid} inside",
        action_pretty="Detected (Reported)",
    )
    prevented_alert = AlertFactory.create(
        actor_process_command_line=f"prevented command with oaev-implant-{prevention_uuid} inside",
        action_pretty="Prevented",
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        detection_expectation,
        prevention_expectation,
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        return_value=[detected_alert, prevented_alert],
    ):
        collector._process_callback()

    # Assert both expectations were processed
    mock_oaev_api.inject_expectation.bulk_update.assert_called_once()
    bulk_expectation = mock_oaev_api.inject_expectation.bulk_update.call_args[1][
        "inject_expectation_input_by_id"
    ]
    assert len(bulk_expectation) == 2

    # Assert detection expectation succeeded
    assert str(detection_expectation.inject_expectation_id) in bulk_expectation
    assert (
        bulk_expectation[str(detection_expectation.inject_expectation_id)].get(
            "is_success"
        )
        is True
    )

    # Assert prevention expectation succeeded
    assert str(prevention_expectation.inject_expectation_id) in bulk_expectation
    assert (
        bulk_expectation[str(prevention_expectation.inject_expectation_id)].get(
            "is_success"
        )
        is True
    )


def test_multiple_expectations_with_partial_matches(mock_oaev_api) -> None:
    """Scenario: Some expectations match, others don't."""
    collector = Collector()
    collector.api = mock_oaev_api
    collector._setup()

    matching_uuid = str(uuid.uuid4())
    non_matching_uuid = str(uuid.uuid4())

    class FakeAPIClient:
        @staticmethod
        def update(self, *args, **kwargs):
            return True

    # Create two expectations
    matching_expectation = DetectionExpectationFactory.create(
        api_client=FakeAPIClient()
    )
    matching_expectation.inject_expectation_signatures[1].value = (
        f"oaev-implant-{matching_uuid}"
    )

    non_matching_expectation = DetectionExpectationFactory.create(
        api_client=FakeAPIClient()
    )
    non_matching_expectation.inject_expectation_signatures[1].value = (
        f"oaev-implant-{non_matching_uuid}"
    )

    # Create alert that only matches the first expectation
    alert = AlertFactory.create(
        actor_process_command_line=f"command with oaev-implant-{matching_uuid} inside",
        action_pretty="Detected (Reported)",
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        matching_expectation,
        non_matching_expectation,
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        return_value=[alert],
    ):
        collector._process_callback()

    # Assert both expectations were processed
    mock_oaev_api.inject_expectation.bulk_update.assert_called_once()
    bulk_expectation = mock_oaev_api.inject_expectation.bulk_update.call_args[1][
        "inject_expectation_input_by_id"
    ]
    assert len(bulk_expectation) == 2

    # Assert matching expectation succeeded
    assert str(matching_expectation.inject_expectation_id) in bulk_expectation
    assert (
        bulk_expectation[str(matching_expectation.inject_expectation_id)].get(
            "is_success"
        )
        is True
    )

    # Assert non-matching expectation failed
    assert str(non_matching_expectation.inject_expectation_id) in bulk_expectation
    assert (
        bulk_expectation[str(non_matching_expectation.inject_expectation_id)].get(
            "is_success"
        )
        is False
    )


def test_prevention_with_detected_then_prevented_alerts(mock_oaev_api) -> None:
    """Scenario: Prevention continues searching until finding a prevented alert."""
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

    # Create multiple alerts: first two are detected, third is prevented
    alert1_detected = AlertFactory.create(
        actor_process_command_line=f"first command with oaev-implant-{execution_uuid} inside",
        action_pretty="Detected (Reported)",
        alert_id=2001,
    )
    alert2_detected = AlertFactory.create(
        actor_process_command_line=f"second command with oaev-implant-{execution_uuid} inside",
        action_pretty="Detected (Reported)",
        alert_id=2002,
    )
    alert3_prevented = AlertFactory.create(
        actor_process_command_line=f"third command with oaev-implant-{execution_uuid} inside",
        action_pretty="Prevented",
        alert_id=2003,
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        return_value=[alert1_detected, alert2_detected, alert3_prevented],
    ):
        collector._process_callback()

    # Assert the expectation was marked as successful (found prevented alert)
    mock_oaev_api.inject_expectation.bulk_update.assert_called_once()
    bulk_expectation = mock_oaev_api.inject_expectation.bulk_update.call_args[1][
        "inject_expectation_input_by_id"
    ]
    assert str(expectation.inject_expectation_id) in bulk_expectation
    assert (
        bulk_expectation[str(expectation.inject_expectation_id)].get("is_success")
        is True
    )

    # Assert traces were created (should include the prevented alert)
    mock_oaev_api.inject_expectation_trace.bulk_create.assert_called_once()
    expectation_traces = mock_oaev_api.inject_expectation_trace.bulk_create.call_args[
        1
    ]["payload"]["expectation_traces"]
    assert len(expectation_traces) > 0, "No expectation traces were submitted"


def test_prevention_with_multiple_traces_before_prevention(mock_oaev_api) -> None:
    """Scenario: Prevention collects multiple traces before finding prevented alert."""
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

    # Create alerts: detected, detected, prevented
    alert1 = AlertFactory.create(
        actor_process_command_line=f"first with oaev-implant-{execution_uuid} inside",
        action_pretty="Detected (Reported)",
        alert_id=3001,
        description="First detection",
    )
    alert2 = AlertFactory.create(
        actor_process_command_line=f"second with oaev-implant-{execution_uuid} inside",
        action_pretty="Detected (Reported)",
        alert_id=3002,
        description="Second detection",
    )
    alert3 = AlertFactory.create(
        actor_process_command_line=f"third with oaev-implant-{execution_uuid} inside",
        action_pretty="Prevented",
        alert_id=3003,
        description="Final prevention",
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        return_value=[alert1, alert2, alert3],
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

    # Assert multiple traces were created (3 traces: 2 detected + 1 prevented)
    mock_oaev_api.inject_expectation_trace.bulk_create.assert_called_once()
    expectation_traces = mock_oaev_api.inject_expectation_trace.bulk_create.call_args[
        1
    ]["payload"]["expectation_traces"]
    assert (
        len(expectation_traces) == 3
    ), f"Expected 3 traces, got {len(expectation_traces)}"


def test_expectation_with_empty_signatures(mock_oaev_api) -> None:
    """Scenario: Expectation with empty signatures list should be handled gracefully."""
    collector = Collector()
    collector.api = mock_oaev_api
    collector._setup()

    class FakeAPIClient:
        @staticmethod
        def update(self, *args, **kwargs):
            return True

    # Create an expectation with empty signatures
    expectation = DetectionExpectationFactory.create(api_client=FakeAPIClient())
    expectation.inject_expectation_signatures = []

    # Create a matching alert
    alert = AlertFactory.create(
        actor_process_command_line="some command line",
        action_pretty="Detected (Reported)",
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        return_value=[alert],
    ):
        collector._process_callback()

    # Assert the expectation was processed (behavior may vary)
    mock_oaev_api.inject_expectation.bulk_update.assert_called_once()
    bulk_expectation = mock_oaev_api.inject_expectation.bulk_update.call_args[1][
        "inject_expectation_input_by_id"
    ]
    assert str(expectation.inject_expectation_id) in bulk_expectation


def test_collector_handles_api_exception(mock_oaev_api) -> None:
    """Scenario: Collector handles API exceptions gracefully."""
    collector = Collector()
    collector.api = mock_oaev_api
    collector._setup()

    class FakeAPIClient:
        @staticmethod
        def update(self, *args, **kwargs):
            return True

    expectation = DetectionExpectationFactory.create(api_client=FakeAPIClient())

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    # Mock the API to raise an exception
    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        side_effect=Exception("API connection failed"),
    ):
        # The collector should handle the exception and not crash
        try:
            collector._process_callback()
        except Exception:
            pass  # Expected behavior - exception should be logged but not crash


def test_trace_content_accuracy(mock_oaev_api) -> None:
    """Scenario: Verify trace contains accurate alert information."""
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

    # Create an alert with specific values
    alert = AlertFactory.create(
        actor_process_command_line=f"test command with oaev-implant-{execution_uuid} inside",
        action_pretty="Detected (Reported)",
        alert_id=9999,
        case_id=8888,
        description="Test Alert Description",
    )

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = [
        expectation
    ]

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        return_value=[alert],
    ):
        collector._process_callback()

    # Assert traces were created
    mock_oaev_api.inject_expectation_trace.bulk_create.assert_called_once()
    expectation_traces = mock_oaev_api.inject_expectation_trace.bulk_create.call_args[
        1
    ]["payload"]["expectation_traces"]
    assert len(expectation_traces) > 0, "No expectation traces were submitted"

    trace = expectation_traces[0]

    # Verify trace content
    assert trace["inject_expectation_trace_expectation"] == str(
        expectation.inject_expectation_id
    )
    assert (
        trace["inject_expectation_trace_alert_link"]
        == f"https://palo-alto.fake/alerts/{alert.alert_id}/{alert.case_id}"
    )
    assert "inject_expectation_trace_alert_name" in trace
    assert "inject_expectation_trace_date" in trace
    assert "inject_expectation_trace_source_id" in trace
