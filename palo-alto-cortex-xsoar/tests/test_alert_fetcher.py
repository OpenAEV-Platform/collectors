from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import ConnectionError, RequestException
from src.models.incident import (
    Alert,
    CustomFields,
    Incident,
    XSOARSearchIncidentsResponse,
)
from src.services.alert_fetcher import AlertFetcher
from src.services.exception import (
    PaloAltoCortexXSOARAPIError,
    PaloAltoCortexXSOARNetworkError,
    PaloAltoCortexXSOARValidationError,
)


@pytest.fixture
def mock_client():
    return MagicMock()


@pytest.fixture
def fetcher(mock_client):
    return AlertFetcher(client_api=mock_client)


def test_init_none_client():
    with pytest.raises(
        PaloAltoCortexXSOARValidationError, match="client_api cannot be None"
    ):
        AlertFetcher(client_api=None)


def test_fetch_alerts_invalid_times(fetcher):
    with pytest.raises(
        PaloAltoCortexXSOARValidationError, match="must be datetime objects"
    ):
        fetcher.fetch_alerts_for_time_window("2023-01-01", datetime.now())

    start = datetime.now()
    end = start - timedelta(hours=1)
    with pytest.raises(
        PaloAltoCortexXSOARValidationError, match="start_time must be before end_time"
    ):
        fetcher.fetch_alerts_for_time_window(start, end)


def test_fetch_alerts_network_error(fetcher, mock_client):
    mock_client.search_incidents.side_effect = ConnectionError("conn error")
    start = datetime.now()
    end = start + timedelta(hours=1)
    with pytest.raises(PaloAltoCortexXSOARNetworkError, match="Network error"):
        fetcher.fetch_alerts_for_time_window(start, end)


def test_fetch_alerts_request_exception(fetcher, mock_client):
    mock_client.search_incidents.side_effect = RequestException("req error")
    start = datetime.now()
    end = start + timedelta(hours=1)
    with pytest.raises(PaloAltoCortexXSOARAPIError, match="HTTP request failed"):
        fetcher.fetch_alerts_for_time_window(start, end)


def test_fetch_alerts_generic_exception(fetcher, mock_client):
    mock_client.search_incidents.side_effect = ValueError("generic error")
    start = datetime.now()
    end = start + timedelta(hours=1)
    with pytest.raises(PaloAltoCortexXSOARAPIError, match="Error fetching alerts"):
        fetcher.fetch_alerts_for_time_window(start, end)


def test_fetch_alerts_pagination(fetcher, mock_client):
    # Mocking two pages of results
    alert1 = Alert(
        alert_id="a1",
        detection_timestamp=1000,
        actor_process_command_line="oaev-implant-1-agent-1",
    )
    alert2 = Alert(
        alert_id="a2",
        detection_timestamp=2000,
        actor_process_command_line="oaev-implant-2-agent-2",
    )

    incident1 = Incident(id="i1", CustomFields=CustomFields(xdralerts=[alert1]))
    incident2 = Incident(id="i2", CustomFields=CustomFields(xdralerts=[alert2]))

    response1 = XSOARSearchIncidentsResponse(total=2, data=[incident1])
    response2 = XSOARSearchIncidentsResponse(total=2, data=[incident2])

    # In AlertFetcher, PAGE_SIZE is 100. Let's force it to 1 for this test or mock multiple calls.
    # _fetch_all_alerts uses a while loop and increments search_from by PAGE_SIZE.
    # It breaks if (search_from + len(response.data)) >= response.total

    # First call: search_from=0, len=1, total=2 -> continues
    # Second call: search_from=100, len=1, total=2 -> (100+1) >= 2 is true -> breaks

    mock_client.search_incidents.side_effect = [response1, response2]

    with patch("src.services.alert_fetcher.PAGE_SIZE", 1):
        start = datetime(2023, 1, 1, tzinfo=timezone.utc)
        end = datetime(2023, 1, 2, tzinfo=timezone.utc)
        result = fetcher.fetch_alerts_for_time_window(start, end)

        assert len(result.alerts) == 2
        assert mock_client.search_incidents.call_count == 2


def test_fetch_alerts_no_alerts(fetcher, mock_client):
    mock_client.search_incidents.return_value = XSOARSearchIncidentsResponse(
        total=0, data=[]
    )
    start = datetime.now()
    end = start + timedelta(hours=1)
    result = fetcher.fetch_alerts_for_time_window(start, end)
    assert result.alerts == []
    assert result.process_names_by_alert_id == {}
