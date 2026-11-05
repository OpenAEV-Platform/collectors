"""Tests for the Logging manager."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
import requests
from pyoaev.apis.inject_expectation.model import LoggingExpectation
from pyoaev.apis.inject_expectation_trace import TraceMatchType
from pyoaev.exceptions import OpenAEVListError, OpenAEVParsingError
from src.collector.exception import TraceSubmissionError
from src.collector.logging_manager import LoggingManager, _Backoff
from src.collector.models import ExpectationTrace
from src.services.exception import SplunkESDataConversionError
from src.services.logging_fetch import (
    LoggingApiError,
    LoggingAuthError,
    LoggingEmpty,
    LoggingMalformed,
    LoggingRows,
)
from src.services.logging_matcher import Match, NoMatch
from src.services.logging_query import LoggingQuery, Unqueryable
from src.services.models import LoggingEvent

COLLECTOR_ID = "collector-1"
PERIOD = timedelta(minutes=1)
MAX_INTERVAL = timedelta(minutes=15)
START = datetime(2026, 11, 3, 8, 0, tzinfo=timezone.utc)
QUERY = LoggingQuery(
    spl="search index IN (sysmon) ...",
    marker_values=["oaev-implant"],
    source_ips=["10.0.0.1"],
    target_ips=[],
    earliest=1_793_692_800,
    latest=1_793_696_400,
)
EVENT = LoggingEvent(event_epoch=1_793_692_900.0, index="sysmon", raw="oaev-implant")


class Clock:
    """Clock the tests move forward."""

    def __init__(self) -> None:
        self.current = START

    def __call__(self) -> datetime:
        return self.current

    def advance(self, delta: timedelta) -> None:
        self.current += delta


def _expectation(end_date: str | None = "2026-11-03T09:00:00Z") -> LoggingExpectation:
    signatures = [{"type": "parent_process_name", "value": "oaev-implant"}]
    if end_date is not None:
        signatures.append({"type": "end_date", "value": end_date})
    return LoggingExpectation(
        inject_expectation_id=uuid4(),
        inject_expectation_signatures=signatures,
        api_client=MagicMock(),
    )


def _trace(expectation_id: str) -> ExpectationTrace:
    return ExpectationTrace(
        inject_expectation_trace_expectation=expectation_id,
        inject_expectation_trace_source_id=COLLECTOR_ID,
        inject_expectation_trace_alert_name="Splunk log event (index=sysmon)",
        inject_expectation_trace_alert_link="https://splunk:8000/search",
        inject_expectation_trace_date="2026-11-03T08:01:40Z",
        inject_expectation_trace_match_type=TraceMatchType.MARKER,
    )


class Harness:
    """A Logging manager with every dependency mocked."""

    def __init__(
        self,
        expectations: list[LoggingExpectation],
        max_interval: timedelta = MAX_INTERVAL,
    ) -> None:
        self.expectations = expectations
        self.api = MagicMock()
        self.api.inject_expectation.logging_expectation_models_for_source.side_effect = (
            self._fetch_expectations
        )
        self.build_query = MagicMock(return_value=QUERY)
        self.fetch_events = MagicMock(return_value=LoggingRows(events=[EVENT]))
        self.matcher = MagicMock()
        self.matcher.match.return_value = Match(
            match_type=TraceMatchType.MARKER, event=EVENT
        )
        self.trace_builder = MagicMock()
        self.trace_builder.build.side_effect = (
            lambda match, query, expectation_id, collector_id: _trace(expectation_id)
        )
        self.on_suspend = MagicMock()
        self.clock = Clock()
        self.manager = LoggingManager(
            oaev_api=self.api,
            collector_id=COLLECTOR_ID,
            build_query=self.build_query,
            fetch_events=self.fetch_events,
            trace_builder=self.trace_builder,
            period=PERIOD,
            max_interval=max_interval,
            on_suspend=self.on_suspend,
            matcher=self.matcher,
            now=self.clock,
        )
        self.submit_traces = MagicMock()
        self.manager.trace_manager._submit_traces = self.submit_traces

    def _fetch_expectations(self, **_) -> list[LoggingExpectation]:
        # As in pyoaev, the models update themselves through the same API:
        # an update sent by a model is checked like the others.
        for expectation in self.expectations:
            expectation._Expectation__api_client = self.api.inject_expectation
        return self.expectations

    def process(self):
        summary = self.manager.process()
        # Every test checks the success-only rule on every update sent.
        self.assert_only_successes_sent()
        return summary

    def bulk_inputs(self) -> list[dict]:
        return [
            c.kwargs["inject_expectation_input_by_id"]
            for c in self.api.inject_expectation.bulk_update.call_args_list
        ]

    def individual_inputs(self) -> list[dict]:
        return [
            c.kwargs["inject_expectation"]
            for c in self.api.inject_expectation.update.call_args_list
        ]

    def assert_only_successes_sent(self) -> None:
        sent = [i for b in self.bulk_inputs() for i in b.values()]
        sent += self.individual_inputs()
        assert all(
            update["is_success"] is True and update["result"] == "Logged"
            for update in sent
        )


def _id(expectation: LoggingExpectation) -> str:
    return str(expectation.inject_expectation_id)


class TestLoggingManagerResults:
    """A match is reported as Logged with its trace; nothing else is sent."""

    def test_match_sends_one_success_and_one_trace(self):
        expectation = _expectation()
        harness = Harness([expectation])

        summary = harness.process()

        assert harness.bulk_inputs() == [
            {
                _id(expectation): {
                    "collector_id": COLLECTOR_ID,
                    "result": "Logged",
                    "is_success": True,
                }
            }
        ]
        traces = harness.submit_traces.call_args.args[0]
        assert [t.inject_expectation_trace_expectation for t in traces] == [
            _id(expectation)
        ]
        assert traces[0].inject_expectation_trace_match_type == TraceMatchType.MARKER
        assert summary.fetched == 1
        assert summary.logged == 1
        assert summary.errors == 0

    def test_trace_is_built_from_the_match_and_the_search(self):
        expectation = _expectation()
        harness = Harness([expectation])
        match = Match(match_type=TraceMatchType.SOURCE_IP, event=EVENT)
        harness.matcher.match.return_value = match

        harness.process()

        harness.matcher.match.assert_called_once_with(QUERY, [EVENT])
        harness.trace_builder.build.assert_called_once_with(
            match, QUERY, _id(expectation), COLLECTOR_ID
        )

    def test_unknown_search_result_is_an_error_not_a_silent_skip(self):
        # E.g. a result type of another module after the Logging search merge.
        harness = Harness([_expectation()])
        harness.fetch_events.return_value = object()

        summary = harness.process()

        harness.api.inject_expectation.bulk_update.assert_not_called()
        assert summary.errors == 1

    def test_empty_search_sends_nothing(self):
        harness = Harness([_expectation()])
        harness.fetch_events.return_value = LoggingEmpty()

        summary = harness.process()

        harness.api.inject_expectation.bulk_update.assert_not_called()
        harness.submit_traces.assert_not_called()
        assert summary.no_match == 1

    def test_no_match_sends_nothing(self):
        harness = Harness([_expectation()])
        harness.matcher.match.return_value = NoMatch()

        summary = harness.process()

        harness.api.inject_expectation.bulk_update.assert_not_called()
        assert summary.no_match == 1

    @pytest.mark.parametrize(
        "error",
        [LoggingApiError("timeout"), LoggingMalformed("not JSON")],
        ids=["api", "malformed"],
    )
    def test_transient_splunk_error_sends_nothing(self, error):
        harness = Harness([_expectation()])
        harness.fetch_events.return_value = error

        summary = harness.process()

        harness.api.inject_expectation.bulk_update.assert_not_called()
        assert summary.errors == 1
        assert summary.suspended is False

    def test_transient_splunk_error_logs_its_reason(self):
        harness = Harness([_expectation()])
        harness.fetch_events.return_value = LoggingApiError(
            "HTTP 400: Error in 'search'"
        )

        with patch.object(harness.manager.logger, "warning") as warning:
            harness.process()

        assert "HTTP 400: Error in 'search'" in warning.call_args.args[0]

    def test_unqueryable_expectation_is_not_searched(self):
        harness = Harness([_expectation()])
        harness.build_query.return_value = Unqueryable("no marker and no IP")

        summary = harness.process()

        harness.fetch_events.assert_not_called()
        harness.api.inject_expectation.bulk_update.assert_not_called()
        assert summary.unqueryable == 1

    def test_unqueryable_from_the_matcher_sends_nothing_and_backs_off(self):
        harness = Harness([_expectation()])
        harness.matcher.match.return_value = Unqueryable("no marker and no IP")

        summary = harness.process()

        harness.api.inject_expectation.bulk_update.assert_not_called()
        assert summary.unqueryable == 1
        assert len(harness.manager._backoff) == 1

    def test_trace_error_skips_the_update(self):
        logged, broken = _expectation(), _expectation()
        harness = Harness([logged, broken])

        def build(match, query, expectation_id, collector_id):
            if expectation_id == _id(broken):
                raise SplunkESDataConversionError("event time out of range")
            return _trace(expectation_id)

        harness.trace_builder.build.side_effect = build

        summary = harness.process()

        assert list(harness.bulk_inputs()[0]) == [_id(logged)]
        assert summary.logged == 1
        assert summary.errors == 1

    def test_trace_error_backs_off(self):
        # The same event would fail again: it must not be searched every cycle.
        harness = Harness([_expectation()])
        harness.trace_builder.build.side_effect = SplunkESDataConversionError(
            "event time out of range"
        )
        harness.process()
        harness.fetch_events.reset_mock()
        harness.clock.advance(PERIOD / 2)

        summary = harness.process()

        harness.fetch_events.assert_not_called()
        assert summary.deferred == 1

    def test_unexpected_error_on_one_expectation_does_not_stop_the_others(self):
        broken, logged = _expectation(), _expectation()
        harness = Harness([broken, logged])
        harness.build_query.side_effect = [RuntimeError("boom"), QUERY]

        summary = harness.process()

        assert list(harness.bulk_inputs()[0]) == [_id(logged)]
        assert summary.errors == 1
        assert summary.logged == 1

    def test_unexpected_error_backs_off(self):
        harness = Harness([_expectation()])
        harness.build_query.side_effect = RuntimeError("boom")
        harness.process()
        harness.build_query.reset_mock()
        harness.clock.advance(PERIOD / 2)

        summary = harness.process()

        harness.build_query.assert_not_called()
        assert summary.deferred == 1


class TestLoggingManagerFetch:
    """The LOGGING expectations fetch never breaks the pass."""

    def test_no_pending_expectation_searches_nothing(self):
        harness = Harness([])

        summary = harness.process()

        harness.fetch_events.assert_not_called()
        harness.api.inject_expectation.bulk_update.assert_not_called()
        assert summary.fetched == 0

    @pytest.mark.parametrize(
        "error",
        [OpenAEVListError("server error"), OpenAEVParsingError("not a list")],
        ids=["http", "malformed-response"],
    )
    def test_fetch_error_is_counted_and_does_not_escape(self, error):
        harness = Harness([_expectation()])
        harness.api.inject_expectation.logging_expectation_models_for_source.side_effect = (
            error
        )

        summary = harness.process()

        harness.fetch_events.assert_not_called()
        harness.api.inject_expectation.bulk_update.assert_not_called()
        assert summary.errors == 1

    def test_network_error_on_fetch_is_counted_and_does_not_escape(self):
        harness = Harness([_expectation()])
        harness.api.inject_expectation.logging_expectation_models_for_source.side_effect = requests.ConnectionError(
            "connection refused"
        )

        summary = harness.process()

        harness.fetch_events.assert_not_called()
        assert summary.errors == 1

    def test_expectation_without_end_date_is_skipped_without_waiting(self):
        harness = Harness([_expectation(end_date=None), _expectation(end_date=" ")])

        with patch("time.sleep") as sleep:
            summary = harness.process()

        sleep.assert_not_called()
        harness.build_query.assert_not_called()
        harness.fetch_events.assert_not_called()
        assert summary.skipped_no_end_date == 2

    def test_expectation_without_end_date_is_searched_once_it_has_one(self):
        expectation = _expectation(end_date=None)
        harness = Harness([expectation])
        harness.process()

        expectation.inject_expectation_signatures = (
            _expectation().inject_expectation_signatures
        )
        summary = harness.process()

        assert summary.logged == 1


class TestLoggingManagerUpdates:
    """Updates fall back to one by one; traces follow the updates."""

    def test_bulk_failure_falls_back_to_individual_updates(self):
        first, second = _expectation(), _expectation()
        harness = Harness([first, second])
        harness.api.inject_expectation.bulk_update.side_effect = RuntimeError("500")

        summary = harness.process()

        updated = [
            c.args[0] for c in harness.api.inject_expectation.update.call_args_list
        ]
        assert updated == [_id(first), _id(second)]
        assert summary.logged == 2
        harness.assert_only_successes_sent()

    def test_traces_are_submitted_only_for_updated_expectations(self):
        updated, failed = _expectation(), _expectation()
        harness = Harness([updated, failed])
        harness.api.inject_expectation.bulk_update.side_effect = RuntimeError("500")
        harness.api.inject_expectation.update.side_effect = [None, RuntimeError("500")]

        summary = harness.process()

        traces = harness.submit_traces.call_args.args[0]
        assert [t.inject_expectation_trace_expectation for t in traces] == [
            _id(updated)
        ]
        assert summary.logged == 1
        assert summary.errors == 1

    def test_failed_update_is_searched_again_one_period_later(self):
        harness = Harness([_expectation()])
        harness.api.inject_expectation.bulk_update.side_effect = RuntimeError("500")
        harness.api.inject_expectation.update.side_effect = RuntimeError("500")
        harness.process()
        harness.fetch_events.reset_mock()
        harness.clock.advance(PERIOD)

        harness.process()

        harness.fetch_events.assert_called_once()

    def test_no_trace_when_every_update_fails(self):
        harness = Harness([_expectation()])
        harness.api.inject_expectation.bulk_update.side_effect = RuntimeError("500")
        harness.api.inject_expectation.update.side_effect = RuntimeError("500")

        summary = harness.process()

        harness.submit_traces.assert_not_called()
        assert summary.logged == 0
        assert summary.errors == 1

    def test_trace_submission_failure_is_counted(self):
        harness = Harness([_expectation()])
        harness.submit_traces.side_effect = TraceSubmissionError("bulk failed")

        summary = harness.process()

        assert summary.logged == 1
        assert summary.errors == 1

    def test_no_code_path_sends_a_failure(self):
        expectations = [_expectation() for _ in range(6)]
        harness = Harness(expectations)
        harness.fetch_events.side_effect = [
            LoggingRows(events=[EVENT]),
            LoggingEmpty(),
            LoggingApiError("timeout"),
            LoggingMalformed("bad"),
            LoggingRows(events=[EVENT]),
            LoggingRows(events=[EVENT]),
        ]
        harness.matcher.match.side_effect = [
            Match(match_type=TraceMatchType.MARKER, event=EVENT),
            NoMatch(),
            Match(match_type=TraceMatchType.SOURCE_IP, event=EVENT),
        ]
        harness.api.inject_expectation.bulk_update.side_effect = RuntimeError("500")

        harness.process()

        assert harness.individual_inputs()
        harness.assert_only_successes_sent()


class TestLoggingManagerSuspension:
    """An access error suspends Logging and withdraws LOGGING."""

    def test_auth_error_suspends_and_stops_the_pass(self):
        harness = Harness([_expectation(), _expectation(), _expectation()])
        harness.fetch_events.side_effect = [
            LoggingRows(events=[EVENT]),
            LoggingAuthError(403),
        ]

        with patch.object(harness.manager.logger, "warning") as warning:
            summary = harness.process()

        assert harness.fetch_events.call_count == 2
        harness.on_suspend.assert_called_once_with()
        warning.assert_called_once()
        assert summary.suspended is True

    @pytest.mark.parametrize(
        ("error", "answer"),
        [
            (
                LoggingAuthError(401, "call not properly authenticated"),
                "(HTTP 401: call not properly authenticated)",
            ),
            (
                LoggingAuthError(403, "insufficient permissions"),
                "(HTTP 403: insufficient permissions)",
            ),
            (LoggingAuthError(403), "(HTTP 403)"),
        ],
        ids=["401", "403", "no-message"],
    )
    def test_suspension_warning_says_what_splunk_answered(self, error, answer):
        harness = Harness([_expectation()])
        harness.fetch_events.return_value = error

        with patch.object(harness.manager.logger, "warning") as warning:
            harness.process()

        assert answer in warning.call_args.args[0]

    def test_matches_found_before_the_auth_error_are_still_reported(self):
        logged = _expectation()
        harness = Harness([logged, _expectation()])
        harness.fetch_events.side_effect = [
            LoggingRows(events=[EVENT]),
            LoggingAuthError(401),
        ]

        summary = harness.process()

        assert list(harness.bulk_inputs()[0]) == [_id(logged)]
        assert summary.logged == 1

    def test_suspended_pass_calls_neither_the_platform_nor_splunk(self):
        harness = Harness([_expectation()])
        harness.fetch_events.return_value = LoggingAuthError(403)
        harness.process()
        harness.api.reset_mock()
        harness.fetch_events.reset_mock()

        summary = harness.process()

        harness.api.inject_expectation.logging_expectation_models_for_source.assert_not_called()
        harness.fetch_events.assert_not_called()
        harness.api.inject_expectation.bulk_update.assert_not_called()
        harness.on_suspend.assert_called_once_with()
        assert summary.suspended is True

    def test_auth_error_sends_nothing_and_does_not_back_off(self):
        expectation = _expectation()
        harness = Harness([expectation])
        harness.fetch_events.return_value = LoggingAuthError(403)

        # The suspension clears the state: watch the calls, not the result.
        with patch.object(harness.manager, "_back_off") as back_off:
            harness.process()

        harness.api.inject_expectation.bulk_update.assert_not_called()
        harness.api.inject_expectation.update.assert_not_called()
        harness.submit_traces.assert_not_called()
        back_off.assert_not_called()

    def test_failure_to_withdraw_logging_still_suspends(self):
        harness = Harness([_expectation()])
        harness.fetch_events.return_value = LoggingAuthError(403)
        harness.on_suspend.side_effect = ValueError("invalid types")

        with patch.object(harness.manager.logger, "warning") as warning:
            summary = harness.process()

        assert summary.suspended is True
        # The failure stays in the suspension: not an expectation error.
        assert summary.errors == 0
        message = warning.call_args.args[0]
        assert "LOGGING could not be withdrawn (invalid types)" in message
        assert "LOGGING is withdrawn" not in message

    def test_suspension_drops_the_search_schedule(self):
        searched, refused = _expectation(), _expectation()
        harness = Harness([searched, refused])
        harness.matcher.match.return_value = NoMatch()
        harness.fetch_events.side_effect = [
            LoggingRows(events=[EVENT]),
            LoggingAuthError(403),
        ]

        harness.process()

        assert harness.manager._backoff == {}


def _slow_harness(count: int, search_seconds: int) -> Harness:
    """A harness whose searches find nothing and take some time each."""
    harness = Harness([_expectation() for _ in range(count)])
    harness.matcher.match.return_value = NoMatch()

    def slow_search(query):
        harness.clock.advance(timedelta(seconds=search_seconds))
        return LoggingRows(events=[EVENT])

    harness.fetch_events.side_effect = slow_search
    return harness


class TestLoggingManagerBudget:
    """A pass starts no search after one period, so Detection is not delayed."""

    def test_pass_stops_searching_after_one_period(self):
        harness = _slow_harness(count=10, search_seconds=25)

        summary = harness.process()

        # Searches start at 0 s, 25 s and 50 s; at 75 s the period is over.
        assert harness.fetch_events.call_count == 3
        assert summary.over_budget == 7
        assert summary.deferred == 0
        assert harness.clock() - START < PERIOD + timedelta(seconds=25)

    def test_expectations_left_over_are_searched_first_next_cycle(self):
        harness = _slow_harness(count=4, search_seconds=40)
        harness.process()
        assert harness.build_query.call_count == 2
        harness.build_query.reset_mock()
        harness.clock.current = START + PERIOD + timedelta(seconds=1)

        harness.process()

        # The two left over by the budget go first, before the two due again.
        searched = [c.args[0] for c in harness.build_query.call_args_list]
        assert [_id(e) for e in searched[:2]] == [
            _id(e) for e in harness.expectations[2:]
        ]

    def test_never_searched_expectations_go_before_due_ones(self):
        old, new = _expectation(), _expectation()
        harness = Harness([old])
        harness.matcher.match.return_value = NoMatch()
        harness.process()
        harness.clock.advance(PERIOD)
        harness.expectations = [old, new]

        harness.process()

        searched = [c.args[0] for c in harness.build_query.call_args_list[1:]]
        assert [_id(e) for e in searched] == [_id(new), _id(old)]

    def test_over_budget_is_logged(self):
        harness = _slow_harness(count=3, search_seconds=60)

        with patch.object(harness.manager.logger, "info") as info:
            harness.process()

        assert any("2 expectations left" in c.args[0] for c in info.call_args_list)

    def test_fast_pass_searches_everything(self):
        harness = _slow_harness(count=20, search_seconds=1)

        summary = harness.process()

        assert harness.fetch_events.call_count == 20
        assert summary.over_budget == 0

    def test_due_expectations_go_by_next_search_time(self):
        late, later, latest = _expectation(), _expectation(), _expectation()
        harness = Harness([latest, late, later])
        for expectation, minutes in ((late, 3), (later, 2), (latest, 1)):
            harness.manager._backoff[_id(expectation)] = _Backoff(
                next_search=START - timedelta(minutes=minutes), interval=PERIOD
            )

        harness.process()

        searched = [c.args[0] for c in harness.build_query.call_args_list]
        assert [_id(e) for e in searched] == [_id(late), _id(later), _id(latest)]

    def test_not_due_expectation_is_deferred_not_over_budget(self):
        slow, waiting = _expectation(), _expectation()
        harness = _slow_harness(count=0, search_seconds=70)
        harness.expectations = [slow, waiting]
        harness.manager._backoff[_id(waiting)] = _Backoff(
            next_search=START + timedelta(hours=1), interval=PERIOD
        )

        summary = harness.process()

        assert summary.deferred == 1
        assert summary.over_budget == 0

    def test_due_time_is_checked_against_the_pass_start(self):
        # A search falling due during a slow pass waits for the next cycle,
        # as the next search times are computed from the pass start.
        slow, due_soon = _expectation(), _expectation()
        harness = _slow_harness(count=0, search_seconds=50)
        harness.expectations = [slow, due_soon]
        harness.manager._backoff[_id(due_soon)] = _Backoff(
            next_search=START + timedelta(seconds=30), interval=PERIOD
        )

        summary = harness.process()

        assert harness.fetch_events.call_count == 1
        assert summary.deferred == 1


class TestLoggingManagerBackoff:
    """An expectation is searched less and less often while nothing is found."""

    def _no_match_harness(self, max_interval: timedelta = MAX_INTERVAL) -> Harness:
        harness = Harness([_expectation()], max_interval=max_interval)
        harness.matcher.match.return_value = NoMatch()
        return harness

    def _searched_at(self, harness: Harness, minutes: int) -> list[int]:
        """Run one pass per minute and return the minutes with a search."""
        searched = []
        for minute in range(minutes):
            before = harness.fetch_events.call_count
            harness.process()
            if harness.fetch_events.call_count > before:
                searched.append(minute)
            harness.clock.advance(PERIOD)
        return searched

    def test_intervals_double_from_the_period(self):
        harness = self._no_match_harness()

        searched = self._searched_at(harness, 16)

        assert searched == [0, 1, 3, 7, 15]

    def test_intervals_stop_at_the_maximum(self):
        harness = self._no_match_harness(max_interval=timedelta(minutes=4))

        searched = self._searched_at(harness, 20)

        assert searched == [0, 1, 3, 7, 11, 15, 19]

    @pytest.mark.parametrize("failure", ["update", "trace", "unexpected"])
    def test_intervals_double_after_a_failure_too(self, failure):
        # A failure that repeats must not search Splunk on every cycle.
        harness = Harness([_expectation()])
        if failure == "update":
            harness.api.inject_expectation.bulk_update.side_effect = RuntimeError()
            harness.api.inject_expectation.update.side_effect = RuntimeError()
        elif failure == "trace":
            harness.trace_builder.build.side_effect = SplunkESDataConversionError(
                "event time out of range"
            )
        else:
            harness.matcher.match.side_effect = RuntimeError("boom")

        searched = self._searched_at(harness, 16)

        assert searched == [0, 1, 3, 7, 15]

    def test_a_successful_update_resets_the_interval(self):
        harness = Harness([_expectation()])
        updates = harness.api.inject_expectation
        updates.bulk_update.side_effect = updates.update.side_effect = RuntimeError()
        assert self._searched_at(harness, 4) == [0, 1, 3]  # next search: minute 7
        updates.bulk_update.side_effect = updates.update.side_effect = None
        harness.clock.advance(timedelta(minutes=3))
        harness.process()
        # Still returned by the platform (e.g. a lost response), failing again.
        updates.bulk_update.side_effect = updates.update.side_effect = RuntimeError()
        harness.clock.advance(PERIOD)

        searched = self._searched_at(harness, 4)

        assert searched == [0, 1, 3]

    def test_slow_searches_do_not_push_the_next_search_past_the_next_cycle(self):
        # The pass time is read once: a search late in a slow pass is due
        # again on the next cycle, one period after the pass started.
        first, second = _expectation(), _expectation()
        harness = self._no_match_harness()
        harness.expectations = [first, second]

        def slow_search(query):
            harness.clock.advance(timedelta(seconds=30))
            return LoggingRows(events=[EVENT])

        harness.fetch_events.side_effect = slow_search
        harness.process()
        harness.clock.current = START + PERIOD
        harness.expectations = [second]
        harness.fetch_events.reset_mock()

        summary = harness.process()

        harness.fetch_events.assert_called_once()
        assert summary.deferred == 0

    def test_deferred_expectation_is_counted_without_a_search(self):
        harness = self._no_match_harness()
        harness.process()
        harness.fetch_events.reset_mock()

        summary = harness.process()

        harness.fetch_events.assert_not_called()
        assert summary.deferred == 1

    @pytest.mark.parametrize(
        "error",
        [LoggingApiError("timeout"), LoggingMalformed("not JSON")],
        ids=["api", "malformed"],
    )
    def test_transient_error_backs_off(self, error):
        harness = Harness([_expectation()])
        harness.fetch_events.return_value = error

        searched = self._searched_at(harness, 4)

        assert searched == [0, 1, 3]

    def test_empty_search_backs_off(self):
        harness = Harness([_expectation()])
        harness.fetch_events.return_value = LoggingEmpty()

        searched = self._searched_at(harness, 4)

        assert searched == [0, 1, 3]

    def test_match_drops_the_state(self):
        harness = Harness([_expectation()])
        harness.matcher.match.side_effect = [
            NoMatch(),
            Match(match_type=TraceMatchType.MARKER, event=EVENT),
        ]
        harness.process()
        harness.clock.advance(PERIOD)

        summary = harness.process()

        assert summary.logged == 1
        assert harness.manager._backoff == {}

    def test_expectation_no_longer_returned_is_pruned(self):
        answered, pending = _expectation(), _expectation()
        harness = self._no_match_harness()
        harness.expectations = [answered, pending]
        harness.process()
        assert set(harness.manager._backoff) == {_id(answered), _id(pending)}

        harness.expectations = [pending]
        harness.process()

        assert set(harness.manager._backoff) == {_id(pending)}

    def test_maximum_below_the_period_means_the_period(self):
        harness = Harness([_expectation()])

        with patch("src.collector.logging_manager.logging.getLogger") as get_logger:
            manager = LoggingManager(
                oaev_api=harness.api,
                collector_id=COLLECTOR_ID,
                build_query=harness.build_query,
                fetch_events=harness.fetch_events,
                trace_builder=harness.trace_builder,
                period=timedelta(minutes=5),
                max_interval=timedelta(minutes=2),
                on_suspend=harness.on_suspend,
            )

        assert manager.max_interval == timedelta(minutes=5)
        get_logger.return_value.warning.assert_called_once()

    def test_maximum_above_the_period_logs_nothing(self):
        harness = Harness([_expectation()])

        with patch("src.collector.logging_manager.logging.getLogger") as get_logger:
            LoggingManager(
                oaev_api=harness.api,
                collector_id=COLLECTOR_ID,
                build_query=harness.build_query,
                fetch_events=harness.fetch_events,
                trace_builder=harness.trace_builder,
                period=PERIOD,
                max_interval=MAX_INTERVAL,
                on_suspend=harness.on_suspend,
            )

        get_logger.return_value.warning.assert_not_called()
