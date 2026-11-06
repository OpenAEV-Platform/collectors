"""Tests for the SentinelOne Unified Alerts fetcher - Gherkin GWT format."""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from requests.exceptions import ConnectionError as RequestsConnectionError
from src.services.exception import SentinelOneAPIError, SentinelOneNetworkError
from src.services.fetcher_unified_alerts import FetcherUnifiedAlerts

IMPLANT = "oaev-implant-91b43a50-910b-4fb3-aae8-a9d70e6f6bd4-agent-a7dbf250"


def _given_fetcher() -> tuple[FetcherUnifiedAlerts, Mock]:
    """Create a Unified Alerts fetcher wired to a mock session.

    Returns:
        Tuple of (fetcher, mock session).

    """
    session = Mock()
    client = Mock()
    client.base_url = "https://s1.example.com"
    client.api_key = "bearer-key-123"
    client.session = session
    return FetcherUnifiedAlerts(client), session


def _response(status: int, payload: dict) -> Mock:
    """Build a mock HTTP response.

    Args:
        status: HTTP status code.
        payload: JSON body.

    Returns:
        Mock response.

    """
    r = Mock()
    r.status_code = status
    r.json.return_value = payload
    r.text = str(payload)
    return r


def _list_page(nodes: list[dict], has_next: bool = False) -> dict:
    """Build an alerts connection page.

    Args:
        nodes: Alert nodes.
        has_next: Whether another page follows.

    Returns:
        GraphQL response body for the alerts list query.

    """
    return {
        "data": {
            "alerts": {
                "pageInfo": {"hasNextPage": has_next, "endCursor": "c1"},
                "edges": [{"node": n} for n in nodes],
            }
        }
    }


def _detail(raw: object) -> dict:
    """Build an alert detail response carrying rawData.

    Args:
        raw: The rawData value.

    Returns:
        GraphQL response body for the detail query.

    """
    return {"data": {"alert": {"rawData": raw}}}


def _window() -> tuple[datetime, datetime]:
    """Return a valid (start, end) window.

    Returns:
        Tuple of two datetimes an hour apart.

    """
    end = datetime(2026, 9, 11, 14, 0, tzinfo=timezone.utc)
    return end - timedelta(hours=1), end


# Scenario: a behavioral alert is mapped to a threat carrying the implant name
def test_behavioral_alert_maps_to_threat_with_implant_event():
    """Scenario: an alert's implant name is recovered from rawData."""
    fetcher, session = _given_fetcher()
    node = {
        "id": "alert-1",
        "name": "Potential Mimikatz Execution",
        "detectedAt": "2026-09-11T13:44:48Z",
        "status": "NEW",
        "result": None,
        "assets": [{"name": "meereen", "osType": "WINDOWS"}],
        "process": {"parentName": None, "cmdLine": "powershell ..."},
    }
    session.post.side_effect = [
        _response(200, _list_page([node])),
        _response(
            200,
            _detail(
                {
                    "process": {"name": "PowerShell.EXE"},
                    "cmd": f"{IMPLANT}.exe launched child",
                }
            ),
        ),
    ]

    start, end = _window()
    threats, events = fetcher.fetch_alert_threats(start, end)

    assert len(threats) == 1
    assert threats[0].threat_id == "alert-1"
    assert threats[0].hostname == "meereen"
    assert threats[0].is_mitigated is False
    parents = [e["parentProcessName"] for e in events["alert-1"]]
    assert f"{IMPLANT}.exe" in parents


# Scenario: a MITIGATED alert is marked as prevented
def test_mitigated_alert_is_marked_mitigated():
    """Scenario: result=MITIGATED sets is_mitigated on the mapped threat."""
    fetcher, session = _given_fetcher()
    node = {
        "id": "alert-2",
        "result": "MITIGATED",
        "assets": [{"name": "demo-vm"}],
        "process": {},
    }
    session.post.side_effect = [
        _response(200, _list_page([node])),
        _response(200, _detail(f"trace {IMPLANT}")),
    ]

    threats, _ = fetcher.fetch_alert_threats(*_window())

    assert threats[0].is_mitigated is True


# Scenario: an alert with no recoverable implant yields no matching event
def test_alert_without_implant_has_no_events():
    """Scenario: no implant in rawData -> empty events (no false positive)."""
    fetcher, session = _given_fetcher()
    node = {"id": "alert-3", "assets": [{"name": "host"}], "process": {}}
    session.post.side_effect = [
        _response(200, _list_page([node])),
        _response(200, _detail("nothing relevant here")),
    ]

    threats, events = fetcher.fetch_alert_threats(*_window())

    assert len(threats) == 1
    assert events.get("alert-3", []) == []


# Scenario: pagination follows the connection cursor
def test_pagination_follows_cursor():
    """Scenario: hasNextPage drives a second list page."""
    fetcher, session = _given_fetcher()
    n1 = {"id": "a1", "assets": [{"name": "h1"}], "process": {}}
    n2 = {"id": "a2", "assets": [{"name": "h2"}], "process": {}}
    # All list pages are walked first, then rawData is fetched per node.
    session.post.side_effect = [
        _response(200, _list_page([n1], has_next=True)),
        _response(200, _list_page([n2], has_next=False)),
        _response(200, _detail(IMPLANT)),
        _response(200, _detail(IMPLANT)),
    ]

    threats, _ = fetcher.fetch_alert_threats(*_window())

    assert {t.threat_id for t in threats} == {"a1", "a2"}


# Scenario: a transport failure raises a transient network error
def test_transport_failure_raises_network_error():
    """Scenario: a connection drop surfaces as SentinelOneNetworkError."""
    fetcher, session = _given_fetcher()
    session.post.side_effect = RequestsConnectionError("boom")

    with pytest.raises(SentinelOneNetworkError):
        fetcher.fetch_alert_threats(*_window())


# Scenario: a GraphQL errors block raises an API error
def test_graphql_errors_raise_api_error():
    """Scenario: a GraphQL validation error surfaces as SentinelOneAPIError."""
    fetcher, session = _given_fetcher()
    session.post.return_value = _response(
        200, {"errors": [{"message": "FieldUndefined"}]}
    )

    with pytest.raises(SentinelOneAPIError):
        fetcher.fetch_alert_threats(*_window())


# Scenario: an HTTP error carries its status code
def test_http_error_carries_status_code():
    """Scenario: a 403 surfaces as SentinelOneAPIError with status_code=403,
    so the service can tell a missing permission from a transient failure."""
    fetcher, session = _given_fetcher()
    session.post.return_value = _response(403, {"errors": "forbidden"})

    with pytest.raises(SentinelOneAPIError) as excinfo:
        fetcher.fetch_alert_threats(*_window())

    assert excinfo.value.status_code == 403  # noqa: S101


def _bare_node(alert_id: str, parent: str | None = None) -> dict:
    """Build a minimal alert node.

    Args:
        alert_id: The alert id.
        parent: Optional process parentName.

    Returns:
        Alert node dict.

    """
    return {
        "id": alert_id,
        "detectedAt": "2026-09-11T13:44:48Z",
        "assets": [{"name": "meereen"}],
        "process": {"parentName": parent, "cmdLine": "powershell ..."},
    }


# Scenario: no detail fetch when the list node already names the implant
def test_detail_not_fetched_when_implant_in_list_node():
    """Scenario: rawData is only fetched when the list fields lack the implant."""
    fetcher, session = _given_fetcher()
    node = _bare_node("alert-1", parent=f"{IMPLANT}.exe")
    session.post.side_effect = [_response(200, _list_page([node]))]

    _threats, events = fetcher.fetch_alert_threats(*_window())

    assert session.post.call_count == 1  # only the list query
    assert f"{IMPLANT}.exe" in [e["parentProcessName"] for e in events["alert-1"]]


# Scenario: alert details are cached across calls
def test_detail_cached_across_calls():
    """Scenario: a second cycle over the same alert reuses its cached rawData."""
    fetcher, session = _given_fetcher()
    node = _bare_node("alert-1")
    session.post.side_effect = [
        _response(200, _list_page([dict(node)])),
        _response(200, _detail({"cmd": f"{IMPLANT}.exe"})),
        _response(200, _list_page([dict(node)])),
    ]

    fetcher.fetch_alert_threats(*_window())
    _threats, events = fetcher.fetch_alert_threats(*_window())

    assert session.post.call_count == 3  # list, detail, list (no 2nd detail)
    assert f"{IMPLANT}.exe" in [e["parentProcessName"] for e in events["alert-1"]]


# Scenario: alerts beyond the detail cap are examined on the next call
def test_detail_cap_resumes_on_next_call(monkeypatch):
    """Scenario: the cap bounds new fetches only, so the next cycle picks up
    the alerts left out, and the late alert's implant is eventually found."""
    import src.services.fetcher_unified_alerts as module

    monkeypatch.setattr(module, "MAX_DETAIL_FETCHES", 1)
    fetcher, session = _given_fetcher()
    nodes = [_bare_node("alert-1"), _bare_node("alert-2")]
    session.post.side_effect = [
        _response(200, _list_page([dict(n) for n in nodes])),
        _response(200, _detail({"cmd": "nothing here"})),
        _response(200, _list_page([dict(n) for n in nodes])),
        _response(200, _detail({"cmd": f"{IMPLANT}.exe"})),
    ]

    _t1, events_first = fetcher.fetch_alert_threats(*_window())
    _t2, events_second = fetcher.fetch_alert_threats(*_window())

    assert "alert-2" not in events_first
    assert f"{IMPLANT}.exe" in [
        e["parentProcessName"] for e in events_second["alert-2"]
    ]
    assert session.post.call_count == 4
