"""Protocol for trace creation services."""

from typing import Protocol

from .models import ExpectationResult, ExpectationTrace


class TraceServiceProvider(Protocol):
    """Protocol for trace creation services."""

    def create_traces_from_results(
        self, results: list[ExpectationResult], collector_id: str
    ) -> list[ExpectationTrace]:
        """Create trace data from processing results.

        Args:
            results: List of ExpectationResult objects to create traces from.
            collector_id: ID of the collector creating the traces.

        Returns:
            List of ExpectationTrace objects for successful expectations.

        """
        ...
