"""Tests for the Splunk ES Logging trace builder and the trace match type."""

import time

import pytest
from pydantic import ValidationError
from pyoaev.apis.inject_expectation_trace import TraceMatchType
from src.collector.models import ExpectationTrace
from src.services.exception import SplunkESDataConversionError
from src.services.logging_matcher import Match
from src.services.logging_query import LoggingQuery
from src.services.logging_trace import LoggingTraceBuilder
from src.services.models import LoggingEvent
from tests.services.fixtures.factories import create_test_config

SPL = 'search index IN (sysmon,wineventlog) ("oaev-implant" OR "10.0.0.50") | head 10'
RAW = "SECRET-RAW-CONTENT user=alice cmd=whoami"
# 2026-11-02T08:35:12Z, with a fraction the trace must drop.
EVENT_EPOCH = 1_793_608_512.734
DETECTION_KEYS = {
    "inject_expectation_trace_expectation",
    "inject_expectation_trace_source_id",
    "inject_expectation_trace_alert_name",
    "inject_expectation_trace_alert_link",
    "inject_expectation_trace_date",
}


def _query() -> LoggingQuery:
    return LoggingQuery(
        spl=SPL,
        marker_values=["oaev-implant"],
        source_ips=[],
        target_ips=["10.0.0.50"],
        earliest=1_793_605_000,
        latest=1_793_612_000,
    )


def _match(match_type=TraceMatchType.MARKER, index: str = "sysmon") -> Match:
    return Match(
        match_type=match_type,
        event=LoggingEvent(
            event_epoch=EVENT_EPOCH,
            index=index,
            host="ws-01",
            sourcetype="XmlWinEventLog",
            raw=RAW,
        ),
    )


def _build(match: Match | None = None, expectation_id: str = "exp-1"):
    return LoggingTraceBuilder(create_test_config()).build(
        match or _match(), _query(), expectation_id, "collector-1"
    )


class TestLoggingTraceBuilder:
    """The trace links the Logging search and dates the chosen event."""

    def test_link_opens_the_logging_search_on_splunk_web(self):
        trace = _build()

        assert trace.inject_expectation_trace_alert_link == (
            "https://test-splunk.example.com:8000/en-US/app/search/search?q="
            "search%20index%20IN%20%28sysmon%2Cwineventlog%29%20"
            "%28%22oaev-implant%22%20OR%20%2210.0.0.50%22%29%20%7C%20head%2010"
            # Splunk's latest is exclusive: one second past the window's end.
            "&earliest=1793605000&latest=1793612001"
        )

    def test_date_is_the_event_time_in_utc_to_the_second(self, monkeypatch):
        # A local timezone far from UTC must not shift the trace date.
        monkeypatch.setenv("TZ", "Pacific/Kiritimati")
        time.tzset()
        try:
            trace = _build()
        finally:
            monkeypatch.undo()
            time.tzset()

        assert trace.inject_expectation_trace_date == "2026-11-02T08:35:12Z"

    def test_date_is_truncated_not_rounded_up(self):
        # Rounding to the microsecond would give 08:35:13.
        match = _match()
        event = match.event.model_copy(update={"event_epoch": 1_793_608_512.9999995})

        trace = _build(Match(match_type=match.match_type, event=event))

        assert trace.inject_expectation_trace_date == "2026-11-02T08:35:12Z"

    def test_event_time_out_of_range_raises_a_conversion_error(self):
        match = _match()
        event = match.event.model_copy(update={"event_epoch": 1e20})

        with pytest.raises(SplunkESDataConversionError):
            _build(Match(match_type=match.match_type, event=event))

    def test_name_contains_the_index_of_the_event(self):
        trace = _build(_match(index="wineventlog"))

        assert trace.inject_expectation_trace_alert_name == (
            "Splunk log event (index=wineventlog)"
        )

    @pytest.mark.parametrize("match_type", list(TraceMatchType))
    def test_match_type_is_sent_as_its_value(self, match_type):
        api_dict = _build(_match(match_type=match_type)).to_api_dict()

        assert api_dict["inject_expectation_trace_match_type"] == match_type.value

    def test_ids_are_set(self):
        api_dict = _build().to_api_dict()

        assert api_dict["inject_expectation_trace_expectation"] == "exp-1"
        assert api_dict["inject_expectation_trace_source_id"] == "collector-1"

    def test_payload_carries_no_event_content(self):
        api_dict = _build().to_api_dict()

        assert set(api_dict) == DETECTION_KEYS | {"inject_expectation_trace_match_type"}
        for value in api_dict.values():
            assert "SECRET-RAW-CONTENT" not in value
            assert "ws-01" not in value
            assert "XmlWinEventLog" not in value

    def test_invalid_trace_raises_a_conversion_error(self):
        with pytest.raises(SplunkESDataConversionError):
            _build(expectation_id=" ")


class TestExpectationTraceMatchType:
    """Traces of the other expectation types keep their payload."""

    def test_detection_payload_has_no_match_type(self):
        trace = ExpectationTrace(
            inject_expectation_trace_expectation="exp-1",
            inject_expectation_trace_source_id="collector-1",
            inject_expectation_trace_alert_name="Splunk ES Detection Alert",
            inject_expectation_trace_alert_link="https://splunk:8000/search",
            inject_expectation_trace_date="2026-11-02T08:35:12Z",
        )

        assert trace.to_api_dict() == {
            "inject_expectation_trace_expectation": "exp-1",
            "inject_expectation_trace_source_id": "collector-1",
            "inject_expectation_trace_alert_name": "Splunk ES Detection Alert",
            "inject_expectation_trace_alert_link": "https://splunk:8000/search",
            "inject_expectation_trace_date": "2026-11-02T08:35:12Z",
        }

    def test_unknown_match_type_is_rejected(self):
        # The platform would drop it silently: fail here instead.
        with pytest.raises(ValidationError):
            ExpectationTrace(
                inject_expectation_trace_expectation="exp-1",
                inject_expectation_trace_source_id="collector-1",
                inject_expectation_trace_alert_name="Splunk log event (index=main)",
                inject_expectation_trace_alert_link="https://splunk:8000/search",
                inject_expectation_trace_date="2026-11-02T08:35:12Z",
                inject_expectation_trace_match_type="hostname",
            )
