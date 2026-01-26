"""Trace Manager for handling expectation traces.

This module provides the TraceManager class which handles all trace-related operations
for expectation processing. It separates trace concerns from the main expectation
"""

import logging
from typing import Any

from pyoaev.client import OpenAEV
from src.collector.exception import (
    TraceCreationError,
    TraceSubmissionError,
    TracingError,
)
from src.collector.models import ExpectationResult
from src.services.trace_service import TraceService

LOG_PREFIX = "[TraceManager]"


class TraceManager:
    """Manages trace creation and submission for expectations.

    This manager handles all trace-related operations, including creating traces
    from expectation results and submitting them to the OpenAEV API.
    """

    def __init__(
        self,
        oaev_api: OpenAEV,
        collector_id: str,
        trace_service: TraceService,
    ) -> None:
        """Initialize trace manager.

        Args:
            oaev_api: OpenAEV API client.
            collector_id: ID of the collector.
            trace_service: Service for creating traces from results.

        """
        self.logger = logging.getLogger(__name__)
        self.oaev_api = oaev_api
        self.collector_id = collector_id
        self.trace_service = trace_service

        self.logger.info(
            f"{LOG_PREFIX} Trace manager initialized for collector: {collector_id}"
        )
        if trace_service:
            self.logger.debug(
                f"{LOG_PREFIX} Trace service available for trace creation"
            )
        else:
            self.logger.debug(
                f"{LOG_PREFIX} No trace service provided - traces will be skipped"
            )

    def create_and_submit_traces(self, results: list[ExpectationResult]) -> None:
        """Create and submit traces from expectation results.

        Creates traces from the provided expectation results using the trace service
        and submits them to the OpenAEV API.

        Args:
            results: List of ExpectationResult objects.

        Raises:
            TracingError: If trace creation or submission fails.

        """
        try:
            if not self.trace_service:
                self.logger.debug(
                    f"{LOG_PREFIX} No trace service provided, skipping trace creation"
                )
                return

            self.logger.debug(
                f"{LOG_PREFIX} Creating traces from {len(results)} expectation results..."
            )
            traces = self.trace_service.create_traces_from_results(
                results, self.collector_id
            )

            if not traces:
                self.logger.info(f"{LOG_PREFIX} No traces created from results")
                return

            self.logger.info(
                f"{LOG_PREFIX} Created {len(traces)} traces, submitting to OpenAEV..."
            )
            self._submit_traces(traces)

        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Error creating and submitting traces: {e} (Context: results_count={len(results)}, collector_id={self.collector_id})"
            )
            raise TracingError(f"Error creating and submitting traces: {e}") from e

    def _submit_traces(self, traces: list[Any]) -> None:
        """Submit traces to the OpenAEV API.

        Converts traces to API format and submits them using bulk creation.
        Falls back to individual creation if bulk submission fails.

        Args:
            traces: List of trace objects to submit.

        Raises:
            TraceSubmissionError: If trace submission fails.

        """
        try:
            self.logger.debug(f"{LOG_PREFIX} Converting traces to API format...")
            trace_dicts = [trace.to_api_dict() for trace in traces]

            if not trace_dicts:
                self.logger.warning(
                    f"{LOG_PREFIX} No trace dictionaries generated from traces"
                )
                return

            self.logger.debug(
                f"{LOG_PREFIX} Submitting {len(trace_dicts)} trace dictionaries to OpenAEV"
            )
            self.logger.debug(
                f"{LOG_PREFIX} Trace data preview: {trace_dicts[:2] if len(trace_dicts) > 2 else trace_dicts}"
            )

            response = self.oaev_api.inject_expectation_trace.bulk_create(
                payload={"expectation_traces": trace_dicts}
            )

            self.logger.info(
                f"{LOG_PREFIX} Successfully created {len(trace_dicts)} expectation traces"
            )
            self.logger.debug(f"{LOG_PREFIX} OpenAEV response: {response}")

        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Bulk trace submission failed: {e}")
            try:
                self.logger.info(
                    f"{LOG_PREFIX} Attempting individual trace creation as fallback..."
                )
                self._fallback_individual_trace_creation(traces)
            except TraceCreationError as fallback_error:
                self.logger.error(
                    f"{LOG_PREFIX} Fallback trace creation also failed: {fallback_error}"
                )
            raise TraceSubmissionError(f"Error submitting traces: {e}") from e

    def _fallback_individual_trace_creation(self, traces: list[Any]) -> None:
        """Fallback method to create traces individually if bulk creation fails.

        Creates traces one by one when bulk creation fails, providing
        resilience for trace submission.

        Args:
            traces: List of trace objects to create individually.

        Raises:
            TraceCreationError: If all individual trace creations fail.

        """
        success_count = 0
        try:
            self.logger.info(
                f"{LOG_PREFIX} Creating {len(traces)} traces individually as fallback"
            )
            error_count = 0

            for i, trace in enumerate(traces, 1):
                try:
                    self.logger.debug(
                        f"{LOG_PREFIX} Creating individual trace {i}/{len(traces)}"
                    )
                    r = self.oaev_api.inject_expectation_trace.create(
                        trace.to_api_dict()
                    )
                    success_count += 1
                    self.logger.debug(
                        f"{LOG_PREFIX} Individual trace {i} created successfully"
                    )
                    self.logger.debug(f"{LOG_PREFIX} Single response: {r}")
                except Exception as individual_error:
                    error_count += 1
                    self.logger.error(
                        f"{LOG_PREFIX} Failed to create individual trace {i}: {individual_error}"
                    )

            self.logger.info(
                f"{LOG_PREFIX} Individual trace creation completed: {success_count} successful, {error_count} failed"
            )

            if success_count == 0:
                raise TraceCreationError("All individual trace creations failed")

        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Error in fallback trace creation: {e} (Context: traces_count={len(traces)}, success_count={success_count})"
            )
            raise TraceCreationError(f"Error in fallback trace creation: {e}") from e
