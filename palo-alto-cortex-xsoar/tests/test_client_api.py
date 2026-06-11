import pytest
from src.models.authentication import Authentication
from src.models.incident import XSOARSearchIncidentsResponse
from src.services.client_api import PaloAltoCortexXSOARClientAPI


@pytest.fixture
def auth():
    return Authentication(api_key="test_key", api_key_id=123)


@pytest.fixture
def api_client(auth):
    return PaloAltoCortexXSOARClientAPI(auth=auth, api_url="https://test.xsoar.com")


def test_search_incidents_returns_valid_dummy_response(api_client):
    response = api_client.search_incidents()

    assert isinstance(response, XSOARSearchIncidentsResponse)
    assert response.total == len(response.data)
    assert response.total >= 1

    for incident in response.data:
        assert incident.id
        assert incident.custom_fields is not None
        assert len(incident.custom_fields.xdralerts) == 1
        alert = incident.custom_fields.xdralerts[0]
        assert alert.alert_id
        assert isinstance(alert.detection_timestamp, int)


def test_search_incidents_accepts_filters_without_external_calls(api_client):
    response = api_client.search_incidents(
        from_date="2026-01-01T00:00:00Z",
        to_date="2026-01-01T23:59:59Z",
        search_from=10,
        search_to=20,
    )

    assert isinstance(response, XSOARSearchIncidentsResponse)
    assert response.total == len(response.data)


def test_search_incidents_can_be_forced_to_multiple_items(api_client, monkeypatch):
    monkeypatch.setattr("src.services.client_api.random.randint", lambda a, b: 2)
    response = api_client.search_incidents()
    assert response.total == 2
    assert len(response.data) == 2


def test_search_incidents_generated_ids_are_unique(api_client):
    response = api_client.search_incidents()
    incident_ids = [incident.id for incident in response.data]
    alert_ids = [
        incident.custom_fields.xdralerts[0].alert_id for incident in response.data
    ]
    assert len(set(incident_ids)) == len(incident_ids)
    assert len(set(alert_ids)) == len(alert_ids)


def test_api_client_stores_api_url():
    """api_url attribute is correctly stored."""
    auth = Authentication(api_key="k", api_key_id=1)
    client = PaloAltoCortexXSOARClientAPI(auth=auth, api_url="https://my.api.com")
    assert client.api_url == "https://my.api.com"
