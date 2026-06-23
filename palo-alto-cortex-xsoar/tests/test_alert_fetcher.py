from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import ConnectionError, RequestException
from src.models.incident import (
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
from src.services.ioc_extractor import IncidentResult, IndicatorResults


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
        AlertFetcher(client_api=None)  # ty:ignore[invalid-argument-type]


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
    with pytest.raises(PaloAltoCortexXSOARAPIError, match="Error fetching incidents"):
        fetcher.fetch_alerts_for_time_window(start, end)


def test_fetch_alerts_pagination(fetcher, mock_client):
    # Mocking two pages of results
    incident1 = Incident(
        id="i1",
        CustomFields=CustomFields(xdralerts=[]),
    )
    incident2 = Incident(
        id="i2",
        CustomFields=CustomFields(xdralerts=[]),
    )

    response1 = XSOARSearchIncidentsResponse(total=2, data=[incident1])
    response2 = XSOARSearchIncidentsResponse(total=2, data=[incident2])

    mock_client.search_incidents.side_effect = [response1, response2]

    with patch("src.services.alert_fetcher.PAGE_SIZE", 1):
        with patch(
            "src.services.alert_fetcher.extract_from_custom_fields"
        ) as mock_extract:
            mock_extract.side_effect = [
                [
                    IncidentResult(
                        id="i1",
                        action=["Detected (Reported)"],
                        indicators=IndicatorResults(
                            oaev_implant=["oaev-implant-1-agent-1"]
                        ),
                    )
                ],
                [
                    IncidentResult(
                        id="i2",
                        action=["Detected (Reported)"],
                        indicators=IndicatorResults(
                            oaev_implant=["oaev-implant-2-agent-2"]
                        ),
                    )
                ],
            ]
            start = datetime(2023, 1, 1, tzinfo=timezone.utc)
            end = datetime(2023, 1, 2, tzinfo=timezone.utc)
            result = fetcher.fetch_alerts_for_time_window(start, end)

            assert len(result) == 2
            assert mock_client.search_incidents.call_count == 2


def test_fetch_alerts_no_alerts(fetcher, mock_client):
    mock_client.search_incidents.return_value = XSOARSearchIncidentsResponse(
        total=0, data=[]
    )
    start = datetime.now()
    end = start + timedelta(hours=1)
    result = fetcher.fetch_alerts_for_time_window(start, end)
    assert result == []


def test_fetch_alerts_timezone_preservation(fetcher, mock_client):
    from datetime import timedelta, timezone

    # Use UTC+2
    tz = timezone(timedelta(hours=2))
    start = datetime(2023, 1, 1, 10, 0, 0, tzinfo=tz)
    end = datetime(2023, 1, 1, 11, 0, 0, tzinfo=tz)

    mock_client.search_incidents.return_value = XSOARSearchIncidentsResponse(
        total=0, data=[]
    )

    fetcher.fetch_alerts_for_time_window(start, end)

    _, kwargs = mock_client.search_incidents.call_args
    assert kwargs["from_date"] == "2023-01-01T10:00:00+02:00"
    assert kwargs["to_date"] == "2023-01-01T11:00:00+02:00"


def test_fetch_alerts_naive_datetime(fetcher, mock_client):
    # Naive datetimes (no timezone)
    start = datetime(2023, 1, 1, 10, 0, 0)
    end = datetime(2023, 1, 1, 11, 0, 0)

    mock_client.search_incidents.return_value = XSOARSearchIncidentsResponse(
        total=0, data=[]
    )

    fetcher.fetch_alerts_for_time_window(start, end)

    _, kwargs = mock_client.search_incidents.call_args
    # It should have an offset now (local time)
    expected_from = (
        start.astimezone().isoformat(timespec="seconds").replace("+00:00", "Z")
    )
    expected_to = end.astimezone().isoformat(timespec="seconds").replace("+00:00", "Z")
    assert kwargs["from_date"] == expected_from
    assert kwargs["to_date"] == expected_to
