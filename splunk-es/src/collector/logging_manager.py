"""Logging Manager.

This module runs the Logging pass of a collection cycle: it searches the
Splunk raw-event indexes for each pending LOGGING expectation and reports the
ones found as "Logged", with a trace.

The pass only ever reports successes: "Not Logged" is written by the platform
when the expectation expires. It never waits: an expectation that cannot be
searched yet is left for a later cycle, and each expectation is searched less
and less often while nothing is found.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, assert_never

from pyoaev.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    LoggingExpectation,
)
from pyoaev.client import OpenAEV  # type: ignore[import-untyped]
from pyoaev.signatures.types import SignatureTypes  # type: ignore[import-untyped]
from src.services.exception import SplunkESDataConversionError
from src.services.logging_fetch import (
    LoggingApiError,
    LoggingAuthError,
    LoggingEmpty,
    LoggingFetchResult,
    LoggingMalformed,
    LoggingRows,
)
from src.services.logging_matcher import LoggingMatcher, Match, NoMatch
from src.services.logging_query import LoggingQuery, Unqueryable
from src.services.logging_trace import LoggingTraceBuilder
from src.services.models import LoggingEvent

from .exception import TraceSubmissionError
from .models import ExpectationTrace
from .trace_manager import TraceManager

LOG_PREFIX = "[CollectorLoggingManager]"

LOGGED_RESULT = "Logged"
# Sorts before any next search time.
NEVER_SEARCHED = datetime.min.replace(tzinfo=timezone.utc)


@dataclass
class LoggingSummary:
    """Counts of one Logging pass.

    Attributes:
        fetched: LOGGING expectations returned by the platform.
        logged: Expectations reported as Logged.
        deferred: Expectations whose next search time was not reached.
        over_budget: Expectations left for the next cycle because the pass
            ran out of time.
        skipped_no_end_date: Expectations without an end date yet.
        unqueryable: Expectations without any marker or IP to search.
        no_match: Searches that found no event of the inject.
        errors: Failed fetches, searches, traces and updates.
        suspended: Whether the Logging pass is suspended.

    """

    fetched: int = 0
    logged: int = 0
    deferred: int = 0
    over_budget: int = 0
    skipped_no_end_date: int = 0
    unqueryable: int = 0
    no_match: int = 0
    errors: int = 0
    suspended: bool = False


@dataclass(frozen=True)
class _Backoff:
    """When an expectation may be searched again."""

    next_search: datetime
    interval: timedelta


class LoggingManager:
    """Runs the Logging pass of each collection cycle.

    The Splunk search is injected (query builder and fetch), so this manager
    only holds the pass logic: success-only updates, search backoff, a time
    budget of one period per pass and suspension on access errors.
    """

    def __init__(
        self,
        oaev_api: OpenAEV,
        collector_id: str,
        build_query: Callable[[LoggingExpectation], LoggingQuery | Unqueryable],
        fetch_events: Callable[[LoggingQuery], LoggingFetchResult],
        trace_builder: LoggingTraceBuilder,
        period: timedelta,
        max_interval: timedelta,
        on_suspend: Callable[[], None],
        matcher: LoggingMatcher | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize the Logging manager.

        Args:
            oaev_api: OpenAEV API client.
            collector_id: ID of the collector.
            build_query: Builds the Logging search of an expectation.
            fetch_events: Runs a Logging search in Splunk.
            trace_builder: Builds the trace of a match.
            period: Collector period, the first search interval.
            max_interval: Longest interval between two searches of an
                expectation. A value below the period means the period.
            on_suspend: Called once when the pass is suspended, to withdraw
                LOGGING from the supported expectation types.
            matcher: Matcher of the returned events.
            now: Clock, for tests.

        """
        self.logger = logging.getLogger(__name__)
        self.oaev_api = oaev_api
        self.collector_id = collector_id
        self.build_query = build_query
        self.fetch_events = fetch_events
        self.trace_builder = trace_builder
        self.period = period
        self.max_interval = max(max_interval, period)
        if max_interval < period:
            self.logger.warning(
                f"{LOG_PREFIX} The Logging max interval ({max_interval}, "
                "SPLUNKES_LOGGING_MAX_INTERVAL, default PT15M) is below the "
                f"collector period: searches back off up to the period ({period})"
            )
        self.on_suspend = on_suspend
        self.matcher = matcher or LoggingMatcher()
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.trace_manager = TraceManager(oaev_api, collector_id)
        self.suspended = False
        self._backoff: dict[str, _Backoff] = {}

    def process(self) -> LoggingSummary:
        """Run one Logging pass.

        Returns:
            The counts of the pass.

        """
        summary = LoggingSummary(suspended=self.suspended)
        if self.suspended:
            return summary

        try:
            expectations = (
                self.oaev_api.inject_expectation.logging_expectation_models_for_source(
                    source_id=self.collector_id
                )
            )
        # HTTP errors come as OpenAEVError, network errors as requests errors.
        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Failed to fetch LOGGING expectations, skipping the "
                f"Logging pass for this cycle: {e}"
            )
            summary.errors += 1
            return summary

        summary.fetched = len(expectations)
        ids = {str(expectation.inject_expectation_id) for expectation in expectations}
        self._backoff = {i: b for i, b in self._backoff.items() if i in ids}

        # One time for the whole pass, so that the next cycle, one period
        # later, reaches the next search time.
        now = self.now()
        # Searches stop after one period, so that Detection, which runs after
        # this pass, is never delayed by much more than a period.
        deadline = now + self.period
        traces: dict[str, ExpectationTrace] = {}
        for expectation in self._most_overdue_first(expectations):
            expectation_id = str(expectation.inject_expectation_id)
            try:
                trace = self._process_expectation(expectation, now, deadline, summary)
            except Exception as e:
                self.logger.error(
                    f"{LOG_PREFIX} Error processing LOGGING expectation "
                    f"{expectation_id}: {e}"
                )
                summary.errors += 1
                self._back_off(expectation_id, now)
                continue
            if self.suspended:
                break
            if trace is not None:
                traces[expectation_id] = trace

        if traces:
            self._report_logged(traces, now, summary)

        if summary.over_budget:
            self.logger.info(
                f"{LOG_PREFIX} Logging pass reached its time budget "
                f"({self.period}): {summary.over_budget} expectations left for "
                "the next cycle"
            )
        summary.suspended = self.suspended
        return summary

    def _report_logged(
        self,
        traces: dict[str, ExpectationTrace],
        now: datetime,
        summary: LoggingSummary,
    ) -> None:
        """Report the matched expectations as Logged, then send their traces.

        Args:
            traces: The trace of each matched expectation, by ID.
            now: Time of the pass.
            summary: Counts of the pass, updated here.

        """
        updated = self._update_logged(list(traces))
        summary.logged = len(updated)
        summary.errors += len(traces) - len(updated)
        for expectation_id in updated:
            self._backoff.pop(expectation_id, None)
        # Not updated: search again later, not on every cycle.
        for expectation_id in traces.keys() - set(updated):
            self._back_off(expectation_id, now)
        if updated:
            summary.errors += self._submit_traces([traces[i] for i in updated])

    def _most_overdue_first(
        self, expectations: list[LoggingExpectation]
    ) -> list[LoggingExpectation]:
        """Order the expectations so that a time budget is shared fairly.

        Args:
            expectations: The LOGGING expectations of the pass.

        Returns:
            The never searched expectations first, in the platform order,
            then the others by next search time.

        """

        def next_search(expectation: LoggingExpectation) -> datetime:
            backoff = self._backoff.get(str(expectation.inject_expectation_id))
            return NEVER_SEARCHED if backoff is None else backoff.next_search

        return sorted(expectations, key=next_search)

    def _process_expectation(
        self,
        expectation: LoggingExpectation,
        now: datetime,
        deadline: datetime,
        summary: LoggingSummary,
    ) -> ExpectationTrace | None:
        """Search one expectation.

        Args:
            expectation: The LOGGING expectation.
            now: Time of the pass.
            deadline: Time after which the pass starts no search.
            summary: Counts of the pass, updated here.

        Returns:
            The trace when the expectation is Logged, otherwise None.

        """
        expectation_id = str(expectation.inject_expectation_id)
        if not self._is_ready(expectation, now, deadline, summary):
            return None

        query = self.build_query(expectation)
        if isinstance(query, Unqueryable):
            self.logger.debug(
                f"{LOG_PREFIX} LOGGING expectation {expectation_id} cannot be "
                f"searched: {query.reason}"
            )
            summary.unqueryable += 1
            return None

        events = self._search(query, expectation_id, now, summary)
        if events is None:
            return None

        match = self.matcher.match(query, events)
        if isinstance(match, Unqueryable):
            self.logger.debug(
                f"{LOG_PREFIX} LOGGING expectation {expectation_id} cannot be "
                f"matched: {match.reason}"
            )
            # The search ran anyway: back off so it does not run every cycle.
            summary.unqueryable += 1
            self._back_off(expectation_id, now)
            return None
        if isinstance(match, NoMatch):
            self.logger.debug(
                f"{LOG_PREFIX} No returned event records LOGGING expectation "
                f"{expectation_id} yet, retrying later"
            )
            summary.no_match += 1
            self._back_off(expectation_id, now)
            return None

        trace = self._build_trace(match, query, expectation_id, summary)
        if trace is None:
            # The same event would fail again: do not search it every cycle.
            self._back_off(expectation_id, now)
        # A trace keeps the backoff until the update succeeds, so a failing
        # update is retried at a growing interval too.
        return trace

    def _is_ready(
        self,
        expectation: LoggingExpectation,
        now: datetime,
        deadline: datetime,
        summary: LoggingSummary,
    ) -> bool:
        """Tell whether an expectation is searched in this pass.

        Args:
            expectation: The LOGGING expectation.
            now: Time of the pass.
            deadline: Time after which the pass starts no search.
            summary: Counts of the pass, updated here.

        Returns:
            True if its search is due, it has an end date and the pass still
            has time.

        """
        backoff = self._backoff.get(str(expectation.inject_expectation_id))
        if backoff is not None and now < backoff.next_search:
            summary.deferred += 1
            return False
        if not self._has_end_date(expectation):
            summary.skipped_no_end_date += 1
            return False
        if self.now() >= deadline:
            summary.over_budget += 1
            return False
        return True

    def _search(
        self,
        query: LoggingQuery,
        expectation_id: str,
        now: datetime,
        summary: LoggingSummary,
    ) -> list[LoggingEvent] | None:
        """Run the Logging search of one expectation.

        Args:
            query: The Logging search.
            expectation_id: ID of the expectation.
            now: Time of the pass.
            summary: Counts of the pass, updated here.

        Returns:
            The returned events, or None when there is nothing to match.

        """
        result = self.fetch_events(query)
        if isinstance(result, LoggingAuthError):
            self._suspend(result)
            return None
        if isinstance(result, LoggingEmpty):
            self.logger.debug(
                f"{LOG_PREFIX} Logging search found no event for expectation "
                f"{expectation_id} yet, retrying later"
            )
            summary.no_match += 1
            self._back_off(expectation_id, now)
            return None
        if isinstance(result, (LoggingApiError, LoggingMalformed)):
            self.logger.warning(
                f"{LOG_PREFIX} Logging search failed for expectation "
                f"{expectation_id} ({type(result).__name__}: {result.message}), "
                "retrying later"
            )
            summary.errors += 1
            self._back_off(expectation_id, now)
            return None
        if not isinstance(result, LoggingRows):
            # A result type this manager does not know: never a silent error.
            assert_never(result)
        return result.events

    def _build_trace(
        self,
        match: Match,
        query: LoggingQuery,
        expectation_id: str,
        summary: LoggingSummary,
    ) -> ExpectationTrace | None:
        """Build the trace of a match; no trace means no update.

        Args:
            match: The matched signal and event.
            query: The Logging search.
            expectation_id: ID of the expectation.
            summary: Counts of the pass, updated here.

        Returns:
            The trace, or None if it cannot be built.

        """
        try:
            return self.trace_builder.build(
                match, query, expectation_id, self.collector_id
            )
        except SplunkESDataConversionError as e:
            self.logger.error(f"{LOG_PREFIX} {e}")
            summary.errors += 1
            return None

    @staticmethod
    def _has_end_date(expectation: LoggingExpectation) -> bool:
        """Tell whether the expectation has its end date yet.

        Args:
            expectation: The LOGGING expectation.

        Returns:
            True if an end date signature has a value.

        """
        return any(
            signature.type == SignatureTypes.SIG_TYPE_END_DATE
            and signature.value.strip()
            for signature in expectation.inject_expectation_signatures
        )

    def _back_off(self, expectation_id: str, now: datetime) -> None:
        """Schedule the next search of an expectation.

        The interval starts at the collector period and doubles after each
        search without a match, up to the maximum interval.

        Args:
            expectation_id: ID of the expectation.
            now: Time of the pass.

        """
        previous = self._backoff.get(expectation_id)
        interval = (
            self.period
            if previous is None
            else min(previous.interval * 2, self.max_interval)
        )
        self._backoff[expectation_id] = _Backoff(
            next_search=now + interval, interval=interval
        )

    def _suspend(self, error: LoggingAuthError) -> None:
        """Stop Logging until the collector restarts, and withdraw LOGGING.

        Args:
            error: What Splunk answered, without credentials.

        """
        self.suspended = True
        self._backoff.clear()
        try:
            self.on_suspend()
            withdrawal = "LOGGING is withdrawn"
        except Exception as e:
            withdrawal = f"LOGGING could not be withdrawn ({e})"
        answer = f"HTTP {error.status_code}"
        if error.message:
            answer += f": {error.message}"
        self.logger.warning(
            f"{LOG_PREFIX} Splunk refused the Logging search ({answer}). "
            "Check that the Splunk account can search the Logging indexes and "
            "that the licence allows it, then restart the collector. Logging "
            f"is suspended and {withdrawal}; Detection goes on."
        )

    def _update_logged(self, expectation_ids: list[str]) -> list[str]:
        """Report expectations as Logged.

        Args:
            expectation_ids: IDs of the matched expectations.

        Returns:
            The IDs that were updated.

        """
        bulk_data = {i: self._logged_input() for i in expectation_ids}
        try:
            self.oaev_api.inject_expectation.bulk_update(
                inject_expectation_input_by_id=bulk_data
            )
            self.logger.info(
                f"{LOG_PREFIX} Reported {len(bulk_data)} LOGGING expectations as Logged"
            )
            return expectation_ids
        except Exception as e:
            self.logger.warning(
                f"{LOG_PREFIX} Bulk update failed, falling back to individual "
                f"updates: {e}"
            )

        updated = []
        for expectation_id, update_data in bulk_data.items():
            try:
                self.oaev_api.inject_expectation.update(
                    expectation_id, inject_expectation=update_data
                )
                updated.append(expectation_id)
            except Exception as e:
                self.logger.error(
                    f"{LOG_PREFIX} Failed to update LOGGING expectation "
                    f"{expectation_id}: {e}"
                )
        return updated

    def _logged_input(self) -> dict[str, Any]:
        """Build the update of a Logged expectation (the only update sent)."""
        return {
            "collector_id": self.collector_id,
            "result": LOGGED_RESULT,
            "is_success": True,
        }

    def _submit_traces(self, traces: list[ExpectationTrace]) -> int:
        """Submit the traces of the updated expectations.

        Args:
            traces: The traces to submit.

        Returns:
            1 if the bulk submission failed, otherwise 0.

        """
        try:
            self.trace_manager._submit_traces(traces)
            return 0
        except TraceSubmissionError as e:
            # Raised even when the individual fallback created some traces.
            self.logger.error(
                f"{LOG_PREFIX} Bulk submission of Logging traces failed: {e}"
            )
            return 1
