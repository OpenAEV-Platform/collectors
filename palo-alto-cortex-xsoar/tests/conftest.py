import uuid
from unittest.mock import patch

import pytest
from pyoaev.signatures.types import SignatureTypes
from src.models.incident import CustomFields, XSOARSearchIncidentsResponse
from src.services.ioc_extractor import IncidentResult, IndicatorResults
from tests.factories import (
    AlertFactory,
    DetectionExpectationFactory,
    IncidentFactory,
)


@pytest.fixture(autouse=True)
def correct_config():
    with patch(
        "os.environ",
        {
            "OPENAEV_URL": "http://url",
            "OPENAEV_TOKEN": "token",
            "COLLECTOR_ID": "collector-id",
            "COLLECTOR_NAME": "collector name",
            "COLLECTOR_LOG_LEVEL": "info",
            "PALO_ALTO_CORTEX_XSOAR_API_URL": "https://palo-alto.fake",
            "PALO_ALTO_CORTEX_XSOAR_API_KEY": "api_key",
            "PALO_ALTO_CORTEX_XSOAR_API_KEY_ID": "1",
            "PALO_ALTO_CORTEX_XSOAR_API_KEY_TYPE": "standard",
        },
    ):
        yield


@pytest.fixture(autouse=True)
def setup_mock():
    with patch("pyoaev.daemons.CollectorDaemon._setup", return_value=True):
        yield


@pytest.fixture
def execution_uuid():
    return str(uuid.uuid4())


@pytest.fixture
def mock_oaev_api():
    with patch("pyoaev.daemons.CollectorDaemon", autospec=True):
        with patch(
            "src.collector.expectation_manager.OpenAEV"
        ) as mock_api_class_em, patch(
            "src.collector.trace_manager.OpenAEV"
        ) as mock_api_class_tm:
            mock_api_instance = mock_api_class_em.return_value
            mock_api_class_tm.return_value = mock_api_instance
            yield mock_api_instance


@pytest.fixture
def expectations(execution_uuid, mock_oaev_api):
    class FakeAPIClient:
        @staticmethod
        def update(self, *args, **kwargs):
            return True

    expectations = DetectionExpectationFactory.create_batch(
        2, api_client=FakeAPIClient()
    )
    expectations[0].inject_expectation_signatures[
        1
    ].value = f"oaev-implant-{execution_uuid}"

    # Set a fixed end_date so we can match it in AlertFetcher
    from datetime import datetime, timezone

    fixed_now = datetime(2026, 4, 27, 11, 0, 0, tzinfo=timezone.utc)
    for exp in expectations:
        for sig in exp.inject_expectation_signatures:
            if sig.type == SignatureTypes.SIG_TYPE_END_DATE:
                sig.value = fixed_now.isoformat().replace("+00:00", "Z")

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = (
        expectations
    )

    return expectations


@pytest.fixture
def alerts(execution_uuid):
    """Create an alert with implant and mock search_incidents + extract_from_custom_fields."""
    agent_uuid = str(uuid.uuid4())
    implant_name = f"oaev-implant-{execution_uuid}-agent-{agent_uuid}"

    alert = AlertFactory.build(
        case_id=42,
        actor_process_command_line=implant_name,
    )

    incident = IncidentFactory.build(custom_fields=CustomFields(xdralerts=[alert]))

    alerts_response = XSOARSearchIncidentsResponse(total=1, data=[incident])

    incident_result = IncidentResult(
        id=str(incident.id),
        action=["Detected (Reported)"],
        indicators=IndicatorResults(oaev_implant=[implant_name]),
    )

    with patch(
        "src.services.client_api.PaloAltoCortexXSOARClientAPI.search_incidents",
        return_value=alerts_response,
    ), patch(
        "src.services.alert_fetcher.extract_from_custom_fields",
        return_value=[incident_result],
    ):
        yield alert
