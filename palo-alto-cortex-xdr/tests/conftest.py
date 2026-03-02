import uuid
from unittest.mock import patch

import pytest
from src.models.alert import (
    AlertEvent,
    GetAlertsResponse,
    GetAlertsResponseItem,
)
from tests.factories import AlertFactory, DetectionExpectationFactory


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
            "PALO_ALTO_CORTEX_XDR_FQDN": "palo-alto.fake",
            "PALO_ALTO_CORTEX_XDR_API_KEY": "api_key",
            "PALO_ALTO_CORTEX_XDR_API_KEY_ID": 1,
            "PALO_ALTO_CORTEX_XDR_API_KEY_TYPE": "standard",
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

    mock_oaev_api.inject_expectation.expectations_models_for_source.return_value = (
        expectations
    )

    return expectations


@pytest.fixture
def alerts(execution_uuid):
    """Create an alert with implant in events and mock get_alerts."""
    alert = AlertFactory(
        case_id=42,
        events=[
            AlertEvent(actor_process_image_name=f"oaev-implant-{execution_uuid}.exe")
        ],
    )

    alerts_response = GetAlertsResponse(
        reply=GetAlertsResponseItem(
            total_count=1,
            result_count=1,
            alerts=[alert],
        )
    )

    with patch(
        "src.services.client_api.PaloAltoCortexXDRClientAPI.get_alerts",
        return_value=alerts_response,
    ):
        yield alert
