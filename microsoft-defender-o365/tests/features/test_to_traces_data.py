"""Gherkin-driven tests for DefenderO365SourceData.to_traces_data() serialization.

Covers:
  - Correct field mapping (title, alertWebUrl, createdDateTime)
  - URL fallback (alertWebUrl -> incidentWebUrl)
  - Missing-URL edge case
  - TraceData.model_dump() round-trip
"""

from datetime import datetime

import pytest
from pydantic import AnyUrl
from src.source.source_data import MicrosoftDefenderO365SourceData

# --- GWT helpers (local to this module per CONTRIBUTING.md) ---


def _given_source_data_with_alert(
    title: str, alert_web_url: str | None, incident_web_url: str | None, created_dt: str
) -> "MicrosoftDefenderO365SourceData":
    """Given a DefenderO365SourceData wrapping a raw alert with the specified fields."""

    alert = {
        "id": "ALT-TEST-001",
        "title": title,
        "alertWebUrl": alert_web_url,
        "incidentWebUrl": incident_web_url,
        "createdDateTime": created_dt,
        "status": "new",
        "severity": "high",
        "evidence": [],
    }
    return MicrosoftDefenderO365SourceData(alert=alert)


def _when_to_traces_data_is_called(source_data):
    """When to_traces_data() is called."""
    return source_data.to_traces_data()


def _then_returned_object_is_trace_data(trace_data):
    """Then the returned object is a TraceData instance."""
    from src.collector.models.data import TraceData

    assert isinstance(trace_data, TraceData)


def _then_trace_data_alert_name_equals(trace_data, expected: str):
    """Then TraceData.alert_name = <expected>."""
    assert trace_data.alert_name == expected


def _then_trace_data_alert_link_equals(trace_data, expected: str):
    """Then TraceData.alert_link equals <expected>."""
    assert str(trace_data.alert_link) == expected


def _then_trace_data_alert_date_equals(trace_data, expected_dt: str):
    """Then TraceData.alert_date equals <expected_dt>."""
    expected = datetime.fromisoformat(expected_dt)
    assert trace_data.alert_date == expected


def _then_trace_data_alert_link_is_valid_any_url(trace_data):
    """Then TraceData.alert_link is a valid AnyUrl."""
    assert isinstance(trace_data.alert_link, AnyUrl)


def _when_trace_data_model_dump_is_called(trace_data):
    """When TraceData.model_dump() is called."""
    return trace_data.model_dump()


def _then_resulting_dict_contains_key(dumped: dict, key: str):
    """Then the resulting dict contains key <key>."""
    assert key in dumped, f"Expected key '{key}' in {dumped.keys()}"


# --- Tests ---


class TestToTracesDataFieldMapping:
    """Scenario Outline: Alert with title, alertWebUrl, and createdDateTime produces valid TraceData."""

    @pytest.mark.parametrize(
        "title,alert_url,created_dt",
        [
            (
                "Phishing email detected",
                "https://security.microsoft.com/alerts/alert-001",
                "2026-07-05T14:00:00Z",
            ),
        ],
    )
    def test_valid_trace_data_produced(
        self, title: str, alert_url: str, created_dt: str
    ) -> None:
        source_data = _given_source_data_with_alert(
            title=title,
            alert_web_url=alert_url,
            incident_web_url=None,
            created_dt=created_dt,
        )
        trace_data = _when_to_traces_data_is_called(source_data)
        _then_returned_object_is_trace_data(trace_data)
        _then_trace_data_alert_name_equals(trace_data, title)
        _then_trace_data_alert_link_equals(trace_data, alert_url)
        _then_trace_data_alert_date_equals(trace_data, created_dt)


class TestToTracesDataUrlFallback:
    """Scenario Outline: alertWebUrl absent causes fallback to incidentWebUrl."""

    @pytest.mark.parametrize(
        "incident_url,title,created_dt",
        [
            (
                "https://security.microsoft.com/incidents/incident-007",
                "Test Alert",
                "2026-07-05T14:00:00Z",
            ),
        ],
    )
    def test_fallback_to_incident_web_url(
        self, incident_url: str, title: str, created_dt: str
    ) -> None:
        source_data = _given_source_data_with_alert(
            title=title,
            alert_web_url=None,
            incident_web_url=incident_url,
            created_dt=created_dt,
        )
        trace_data = _when_to_traces_data_is_called(source_data)
        _then_returned_object_is_trace_data(trace_data)
        _then_trace_data_alert_link_equals(trace_data, incident_url)


class TestToTracesDataMissingUrlEdgeCase:
    """Scenario: Both alertWebUrl and incidentWebUrl absent (missing-URL edge case)."""

    @pytest.mark.parametrize(
        "title,created_dt",
        [
            ("No Link", "2026-07-05T14:00:00Z"),
        ],
    )
    def test_missing_url_edge_case(self, title: str, created_dt: str) -> None:
        source_data = _given_source_data_with_alert(
            title=title,
            alert_web_url=None,
            incident_web_url=None,
            created_dt=created_dt,
        )
        trace_data = _when_to_traces_data_is_called(source_data)
        _then_returned_object_is_trace_data(trace_data)
        _then_trace_data_alert_link_is_valid_any_url(trace_data)


class TestTraceDataModelDumpRoundTrip:
    """Scenario: TraceData.model_dump() round-trip preserves keys."""

    def test_model_dump_preserves_keys(self) -> None:
        source_data = _given_source_data_with_alert(
            title="Test Alert",
            alert_web_url="https://security.microsoft.com/alerts/test-001",
            incident_web_url=None,
            created_dt="2026-07-05T14:00:00Z",
        )
        trace_data = _when_to_traces_data_is_called(source_data)
        dumped = _when_trace_data_model_dump_is_called(trace_data)
        _then_resulting_dict_contains_key(dumped, "alert_name")
        _then_resulting_dict_contains_key(dumped, "alert_link")
        _then_resulting_dict_contains_key(dumped, "alert_date")
