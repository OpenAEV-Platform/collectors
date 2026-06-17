from unittest.mock import patch

import pytest
import requests
from src.models.authentication import Authentication
from src.models.incident import XSOARSearchIncidentsResponse
from src.services.client_api import PaloAltoCortexXSOARClientAPI


@pytest.fixture
def auth():
    return Authentication(api_key="test_key", api_key_id=123)


@pytest.fixture
def api_client(auth):
    return PaloAltoCortexXSOARClientAPI(auth=auth, api_url="https://test.xsoar.com")


def test_search_incidents_success(api_client):
    mock_response = {
        "total": 1,
        "data": [
            {
                "id": "1",
                "name": "Test Incident",
                "CustomFields": {
                    "xdralerts": [
                        {"alert_id": "alert1", "detection_timestamp": 1600000000000}
                    ]
                },
            }
        ],
    }

    with patch("requests.Session.post") as mock_post:
        mock_post.return_value.json.return_value = mock_response
        mock_post.return_value.status_code = 200

        response = api_client.search_incidents(
            from_date="2023-01-01T00:00:00Z",
            to_date="2023-01-01T23:59:59Z",
            search_from=0,
            search_to=10,
        )

        assert isinstance(response, XSOARSearchIncidentsResponse)
        assert response.total == 1
        assert len(response.data) == 1
        assert response.data[0].id == "1"
        assert response.data[0].custom_fields.xdralerts[0].alert_id == "alert1"

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == "https://test.xsoar.com/xsoar/public/v1/incidents/search"
        assert kwargs["json"]["filter"]["size"] == 10
        assert kwargs["json"]["filter"]["page"] == 0
        assert kwargs["json"]["filter"]["fromDate"] == "2023-01-01T00:00:00Z"
        assert kwargs["json"]["filter"]["toDate"] == "2023-01-01T23:59:59Z"


def test_search_incidents_http_error(api_client):
    with patch("requests.Session.post") as mock_post:
        mock_post.return_value.raise_for_status.side_effect = (
            requests.exceptions.HTTPError("Error")
        )

        with pytest.raises(requests.exceptions.HTTPError):
            api_client.search_incidents()


def test_search_incidents_pagination(api_client):
    with patch("requests.Session.post") as mock_post:
        mock_post.return_value.json.return_value = {"total": 0, "data": []}

        api_client.search_incidents(search_from=20, search_to=30)

        _, kwargs = mock_post.call_args
        assert kwargs["json"]["filter"]["size"] == 10
        assert kwargs["json"]["filter"]["page"] == 2


# --- New tests ---


def test_search_incidents_no_dates(api_client):
    """When no dates are provided, fromDate and toDate are absent."""
    with patch("requests.Session.post") as mock_post:
        mock_post.return_value.json.return_value = {"total": 0, "data": []}
        api_client.search_incidents()
        _, kwargs = mock_post.call_args
        assert "fromDate" not in kwargs["json"]["filter"]
        assert "toDate" not in kwargs["json"]["filter"]


def test_search_incidents_only_from_date(api_client):
    """When only from_date is provided, toDate is absent."""
    with patch("requests.Session.post") as mock_post:
        mock_post.return_value.json.return_value = {"total": 0, "data": []}
        api_client.search_incidents(from_date="2026-01-01T00:00:00Z")
        _, kwargs = mock_post.call_args
        assert kwargs["json"]["filter"]["fromDate"] == "2026-01-01T00:00:00Z"
        assert "toDate" not in kwargs["json"]["filter"]


def test_search_incidents_only_to_date(api_client):
    """When only to_date is provided, fromDate is absent."""
    with patch("requests.Session.post") as mock_post:
        mock_post.return_value.json.return_value = {"total": 0, "data": []}
        api_client.search_incidents(to_date="2026-12-31T23:59:59Z")
        _, kwargs = mock_post.call_args
        assert "fromDate" not in kwargs["json"]["filter"]
        assert kwargs["json"]["filter"]["toDate"] == "2026-12-31T23:59:59Z"


def test_search_incidents_zero_size(api_client):
    """When search_from == search_to, size is 0 and page is 0."""
    with patch("requests.Session.post") as mock_post:
        mock_post.return_value.json.return_value = {"total": 0, "data": []}
        api_client.search_incidents(search_from=5, search_to=5)
        _, kwargs = mock_post.call_args
        assert kwargs["json"]["filter"]["size"] == 0
        assert kwargs["json"]["filter"]["page"] == 0


def test_search_incidents_default_page_size(api_client):
    """Default search_from=0, search_to=100 gives size=100, page=0."""
    with patch("requests.Session.post") as mock_post:
        mock_post.return_value.json.return_value = {"total": 0, "data": []}
        api_client.search_incidents()
        _, kwargs = mock_post.call_args
        assert kwargs["json"]["filter"]["size"] == 100
        assert kwargs["json"]["filter"]["page"] == 0


def test_search_incidents_headers_sent(api_client, auth):
    """Auth headers are included in the request."""
    expected_headers = auth.get_headers()
    with patch("requests.Session.post") as mock_post:
        mock_post.return_value.json.return_value = {"total": 0, "data": []}
        api_client.search_incidents()
        _, kwargs = mock_post.call_args
        assert kwargs["headers"] == expected_headers


def test_search_incidents_sort_order(api_client):
    """Request body always includes sort by 'created' ascending."""
    with patch("requests.Session.post") as mock_post:
        mock_post.return_value.json.return_value = {"total": 0, "data": []}
        api_client.search_incidents()
        _, kwargs = mock_post.call_args
        assert kwargs["json"]["filter"]["sort"] == [{"field": "created", "asc": True}]


def test_search_incidents_connection_error(api_client):
    """Connection errors propagate."""
    with patch(
        "requests.Session.post",
        side_effect=requests.exceptions.ConnectionError("no route"),
    ):
        with pytest.raises(requests.exceptions.ConnectionError):
            api_client.search_incidents()


def test_search_incidents_timeout(api_client):
    """Timeout errors propagate."""
    with patch(
        "requests.Session.post", side_effect=requests.exceptions.Timeout("timed out")
    ):
        with pytest.raises(requests.exceptions.Timeout):
            api_client.search_incidents()


def test_search_incidents_multiple_incidents(api_client):
    """Response with multiple incidents is parsed correctly."""
    mock_response = {
        "total": 2,
        "data": [
            {
                "id": "1",
                "name": "Inc 1",
                "CustomFields": {
                    "xdralerts": [{"alert_id": "a1", "detection_timestamp": 1000}]
                },
            },
            {
                "id": "2",
                "name": "Inc 2",
                "CustomFields": {
                    "xdralerts": [{"alert_id": "a2", "detection_timestamp": 2000}]
                },
            },
        ],
    }
    with patch("requests.Session.post") as mock_post:
        mock_post.return_value.json.return_value = mock_response
        response = api_client.search_incidents()
        assert response.total == 2
        assert len(response.data) == 2
        assert response.data[1].custom_fields.xdralerts[0].alert_id == "a2"


def test_api_client_stores_api_url():
    """api_url attribute is correctly stored."""
    auth = Authentication(api_key="k", api_key_id=1)
    client = PaloAltoCortexXSOARClientAPI(auth=auth, api_url="https://my.api.com")
    assert client.api_url == "https://my.api.com"
