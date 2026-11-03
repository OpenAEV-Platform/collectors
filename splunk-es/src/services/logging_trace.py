"""Splunk ES Logging trace builder.

This module turns a Logging match into the expectation trace sent to
OpenAEV. The trace says which signal matched, when the event happened and
how to open the Logging search in Splunk Web; it never carries raw log
content.
"""

import logging
import math
from datetime import datetime, timezone

from ..collector.models import ExpectationTrace
from ..models.configs.config_loader import ConfigLoader
from .exception import SplunkESDataConversionError
from .logging_matcher import Match
from .logging_query import LoggingQuery
from .utils.search_url import build_search_url

LOG_PREFIX = "[SplunkESLoggingTrace]"


class LoggingTraceBuilder:
    """Build the expectation trace of a Logging match."""

    def __init__(self, config: ConfigLoader) -> None:
        """Initialize the trace builder.

        Args:
            config: Configuration loader, for the Splunk base URL.

        """
        self.logger = logging.getLogger(__name__)
        self.config = config

    def build(
        self,
        match: Match,
        query: LoggingQuery,
        expectation_id: str,
        collector_id: str,
    ) -> ExpectationTrace:
        """Build the trace of a matched LOGGING expectation.

        Args:
            match: The matched signal and event.
            query: The Logging search that returned the event.
            expectation_id: ID of the LOGGING expectation.
            collector_id: ID of the collector.

        Returns:
            The trace: Logging search link, event time in UTC, index of the
            event and match type.

        Raises:
            SplunkESDataConversionError: If the trace cannot be built (e.g.
                empty ID, event time out of range).

        """
        try:
            trace = ExpectationTrace(
                inject_expectation_trace_expectation=expectation_id,
                inject_expectation_trace_source_id=collector_id,
                inject_expectation_trace_alert_name=(
                    f"Splunk log event (index={match.event.index})"
                ),
                # The window is also in the SPL; repeating it in the link keeps
                # the right range if the SPL ever loses it. Splunk's latest is
                # exclusive, the window's is not.
                inject_expectation_trace_alert_link=build_search_url(
                    str(self.config.splunk_es.base_url),
                    query.spl,
                    earliest=query.earliest,
                    latest=query.latest + 1,
                ),
                inject_expectation_trace_date=self._utc_date(match.event.event_epoch),
                inject_expectation_trace_match_type=match.match_type,
            )
        # ValueError covers pydantic validation and NaN; OverflowError and
        # OSError an event time out of the platform's range.
        except (ValueError, OverflowError, OSError) as e:
            raise SplunkESDataConversionError(
                f"Error creating Logging trace for expectation {expectation_id}: {e}"
            ) from e

        self.logger.debug(
            f"{LOG_PREFIX} Created Logging trace for expectation {expectation_id}: "
            f"{match.match_type.value} at {trace.inject_expectation_trace_date}"
        )
        return trace

    @staticmethod
    def _utc_date(event_epoch: float) -> str:
        """Format an event time for the platform.

        Args:
            event_epoch: Event time as Unix epoch seconds.

        Returns:
            The time in UTC, ISO-8601 with a ``Z`` suffix, to the second (the
            platform stores the trace date without fractions).

        """
        # Truncate first: fromtimestamp rounds to the microsecond, which would
        # turn 21.9999999 into the next second.
        event_time = datetime.fromtimestamp(math.floor(event_epoch), tz=timezone.utc)
        return event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
