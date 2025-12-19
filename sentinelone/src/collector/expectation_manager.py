"""Generic Expectation Manager."""

import logging
from typing import Any

from pyoaev.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    DetectionExpectation, PreventionExpectation)
from pyoaev.client import OpenAEV  # type: ignore[import-untyped]
from pyoaev.helpers import \
    OpenAEVDetectionHelper  # type: ignore[import-untyped]

from .exception import (APIError, BulkUpdateError, ExpectationProcessingError,
                        ExpectationUpdateError)
from .expectation_handler import GenericExpectationHandler
from .models import ExpectationResult, ProcessingSummary
from .trace_manager import TraceManager
from .trace_service_provider import TraceServiceProvider

LOG_PREFIX = "[CollectorExpectationManager]"


class GenericExpectationManager:
    """Generic expectation manager that works with any service provider.

    This manager is completely agnostic to the specific use case and
    delegates all processing logic to the injected service providers.
    """

    def __init__(
        self,
        oaev_api: OpenAEV,
        collector_id: str,
        expectation_handler: GenericExpectationHandler,
        trace_service: TraceServiceProvider | None = None,
    ) -> None:
        """Initialize generic expectation manager.

        Args:
            oaev_api: OpenAEV API client.
            collector_id: ID of the collector.
            expectation_handler: Handler for processing expectations.
            trace_service: Optional service for creating traces.

        Raises:
            ValueError: If required parameters are None or empty.

        """
        if not oaev_api:
            raise ValueError("oaev_api cannot be None")
        if not collector_id:
            raise ValueError("collector_id cannot be empty")
        if not expectation_handler:
            raise ValueError("expectation_handler cannot be None")

        self.logger = logging.getLogger(__name__)
        self.oaev_api = oaev_api
        self.collector_id = collector_id
        self.expectation_handler = expectation_handler
        self.trace_manager = TraceManager(
            oaev_api=oaev_api,
            collector_id=collector_id,
            trace_service=trace_service,
        )

        self.logger.info(
            f"{LOG_PREFIX} Expectation manager initialized for collector: {collector_id}"
        )

    def process_expectations(
        self, detection_helper: OpenAEVDetectionHelper
    ) -> ProcessingSummary:
        """Process all expectations using the injected handler.

        Fetches expectations from OpenAEV, processes them through the handler,
        updates expectations in OpenAEV, and creates traces.

        Args:
            detection_helper: OpenAEV detection helper.

        Returns:
            ProcessingSummary containing processing results.

        Raises:
            ExpectationProcessingError: If processing fails.

        """
        try:
            self.logger.info(f"{LOG_PREFIX} Starting expectation processing cycle")

            self.logger.debug(f"{LOG_PREFIX} Fetching expectations from OpenAEV...")
            expectations = self._fetch_expectations()

            if not expectations:
                self.logger.warning(f"{LOG_PREFIX} No expectations found to process")
                return ProcessingSummary(
                    processed=0,
                    valid=0,
                    invalid=0,
                    skipped=0,
                    total_processing_time=None,
                )

            supported_expectations = [
                exp
                for exp in expectations
                if isinstance(exp, (DetectionExpectation, PreventionExpectation))
            ]

            total_expectations = len(expectations)
            supported_count = len(supported_expectations)
            skipped_count = total_expectations - supported_count

            self.logger.info(
                f"{LOG_PREFIX} Found {total_expectations} total expectations: "
                f"{supported_count} supported, {skipped_count} skipped"
            )

            if skipped_count > 0:
                self.logger.debug(
                    f"{LOG_PREFIX} Skipped {skipped_count} unsupported expectation types"
                )

            self.logger.debug(
                f"{LOG_PREFIX} Processing expectations through handler..."
            )
            results, service_skipped_count = (
                self.expectation_handler.handle_batch_expectations(
                    supported_expectations, detection_helper
                )
            )

            self.logger.debug(f"{LOG_PREFIX} Updating expectations in OpenAEV...")
            self._bulk_update_expectations(results)

            self.logger.debug(f"{LOG_PREFIX} Creating and submitting traces...")
            self.trace_manager.create_and_submit_traces(results)

            valid_count = sum(1 for r in results if r.is_valid)
            invalid_count = len(results) - valid_count

            total_skipped = skipped_count + service_skipped_count

            summary = ProcessingSummary(
                processed=len(results),
                valid=valid_count,
                invalid=invalid_count,
                skipped=total_skipped,
                total_processing_time=None,
            )

            self.logger.info(
                f"{LOG_PREFIX} Expectation processing: processed {total_expectations} items -> {len(results)} results"
            )

            self.logger.info(
                f"{LOG_PREFIX} Processing cycle completed: {valid_count} valid, "
                f"{invalid_count} invalid, {total_skipped} skipped ({skipped_count} unsupported types, {service_skipped_count} no end_date)"
            )

            return summary

        except (BulkUpdateError, APIError) as e:
            self.logger.error(f"{LOG_PREFIX} API operation failed: {e}")
            raise ExpectationProcessingError(f"API error during processing: {e}") from e
        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Unexpected error during processing: {e}")
            raise ExpectationProcessingError(
                f"Unexpected error processing expectations: {e}"
            ) from e

    def _bulk_update_expectations(self, results: list[ExpectationResult]) -> None:
        """Bulk update expectations in OpenAEV.

        Prepares bulk data from results and attempts to update expectations
        using the OpenAEV bulk update API.

        Args:
            results: List of ExpectationResult objects to update.

        Raises:
            BulkUpdateError: If bulk update fails.

        """
        if not results:
            self.logger.debug(
                f"{LOG_PREFIX} No results to update, skipping bulk update"
            )
            return

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Preparing bulk data for {len(results)} results..."
            )
            bulk_data = self._prepare_bulk_data(results)

            if bulk_data:
                self.logger.debug(
                    f"{LOG_PREFIX} Attempting bulk update of {len(bulk_data)} expectations..."
                )
                self._attempt_bulk_update(bulk_data)
            else:
                self.logger.debug(
                    f"{LOG_PREFIX} No valid bulk data prepared, skipping update"
                )

        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Bulk update failed: {e}")
            raise BulkUpdateError(f"Error in bulk update: {e}") from e

    def _prepare_bulk_data(
        self, results: list[ExpectationResult]
    ) -> dict[str, dict[str, Any]]:
        """Prepare bulk data from results.

        Transforms ExpectationResult objects into dictionary format
        required by the OpenAEV bulk update API.

        Args:
            results: List of ExpectationResult objects.

        Returns:
            Dictionary mapping expectation IDs to update data.

        """
        bulk_data = {}
        skipped_count = 0

        for result in results:
            try:
                expectation_id = result.expectation_id
                if not expectation_id:
                    skipped_count += 1
                    self.logger.debug(
                        f"{LOG_PREFIX} Skipping result without expectation_id"
                    )
                    continue

                is_valid = result.is_valid
                expectation = result.expectation
                if expectation:
                    result_text = self._get_result_text(expectation, is_valid)
                    bulk_data[expectation_id] = {
                        "collector_id": self.collector_id,
                        "result": result_text,
                        "is_success": is_valid,
                    }
                    self.logger.debug(
                        f"{LOG_PREFIX} Prepared update for expectation {expectation_id}: "
                        f"result='{result_text}', success={is_valid}"
                    )
                else:
                    skipped_count += 1
                    self.logger.debug(
                        f"{LOG_PREFIX} Skipping result {expectation_id} without expectation object"
                    )
            except Exception as e:
                skipped_count += 1
                self.logger.warning(f"{LOG_PREFIX} Error processing result: {e}")

        if skipped_count > 0:
            self.logger.debug(
                f"{LOG_PREFIX} Skipped {skipped_count} results during bulk data preparation"
            )
        return bulk_data

    def _get_result_text(
        self, expectation: DetectionExpectation | PreventionExpectation, is_valid: bool
    ) -> str:
        """Get result text based on expectation type and validity.

        Args:
            expectation: The expectation object (Detection or Prevention).
            is_valid: Whether the expectation was successfully validated.

        Returns:
            Human-readable result text for the expectation.

        """
        try:
            base_text = (
                "Detected"
                if isinstance(expectation, DetectionExpectation)
                else "Prevented"
            )
            result_text = base_text if is_valid else f"Not {base_text}"

            self.logger.debug(
                f"{LOG_PREFIX} Generated result text: '{result_text}' for {type(expectation).__name__}"
            )
            return result_text
        except Exception as e:
            self.logger.warning(f"{LOG_PREFIX} Error generating result text: {e}")
            return "Unknown"

    def _attempt_bulk_update(self, bulk_data: dict[str, dict[str, Any]]) -> None:
        """Attempt bulk update with fallback to individual updates.

        Tries to use the bulk update API first, then falls back to individual
        updates if the bulk operation fails.

        Args:
            bulk_data: Dictionary of expectation updates to apply.

        Raises:
            BulkUpdateError: If both bulk and individual updates fail.

        """
        try:
            self.logger.debug(f"{LOG_PREFIX} Attempting bulk update via OpenAEV API...")
            self.oaev_api.inject_expectation.bulk_update(
                inject_expectation_input_by_id=bulk_data
            )
            self.logger.info(
                f"{LOG_PREFIX} Successfully bulk updated {len(bulk_data)} expectations"
            )

        except Exception as bulk_error:
            self.logger.warning(
                f"{LOG_PREFIX} Bulk update failed, falling back to individual updates: {bulk_error}"
            )
            try:
                self._fallback_individual_updates(bulk_data)
            except Exception as fallback_error:
                raise BulkUpdateError(
                    f"Both bulk and individual updates failed: {fallback_error}"
                ) from fallback_error

    def _fallback_individual_updates(
        self, bulk_data: dict[str, dict[str, Any]]
    ) -> None:
        """Fallback to individual expectation updates.

        Updates expectations one by one when bulk update fails.

        Args:
            bulk_data: Dictionary of expectation updates to apply.

        """
        self.logger.info(
            f"{LOG_PREFIX} Attempting individual updates for {len(bulk_data)} expectations"
        )
        success_count = 0
        error_count = 0

        for expectation_id, update_data in bulk_data.items():
            try:
                self._update_expectation(expectation_id, update_data)
                success_count += 1
            except (APIError, ExpectationUpdateError) as e:
                error_count += 1
                self.logger.error(
                    f"{LOG_PREFIX} Failed to update expectation {expectation_id}: {e}"
                )
            except Exception as e:
                error_count += 1
                self.logger.error(
                    f"{LOG_PREFIX} Unexpected error updating expectation {expectation_id}: {e}"
                )

        self.logger.info(
            f"{LOG_PREFIX} Individual updates completed: {success_count} successful, {error_count} failed"
        )

    def _update_expectation(
        self, expectation_id: str, update_data: dict[str, Any]
    ) -> None:
        """Update a single expectation.

        Args:
            expectation_id: ID of the expectation to update.
            update_data: Update data to apply to the expectation.

        Raises:
            ExpectationUpdateError: If the update fails.

        """
        self.logger.debug(
            f"{LOG_PREFIX} Updating individual expectation: {expectation_id}"
        )

        try:
            self.oaev_api.inject_expectation.update(
                inject_expectation_id=expectation_id,
                inject_expectation=update_data,
            )
            self.logger.debug(
                f"{LOG_PREFIX} Successfully updated expectation {expectation_id}"
            )

        except Exception as individual_error:
            raise ExpectationUpdateError(
                f"Failed to update expectation {expectation_id}: {individual_error}"
            ) from individual_error

    def _fetch_expectations(
        self,
    ) -> list[DetectionExpectation | PreventionExpectation]:
        """Fetch expectations from OpenAEV.

        Returns:
            List of expectations.

        """
        self.logger.debug(
            f"{LOG_PREFIX} Fetching expectations for collector: {self.collector_id}"
        )

        try:
            expectations = (
                self.oaev_api.inject_expectation.expectations_models_for_source(
                    source_id=self.collector_id
                )
            )
            self.logger.debug(
                f"{LOG_PREFIX} Fetched {len(expectations)} expectations, reversing order..."
            )
            expectations = list(reversed(expectations))
            return expectations
        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Error fetching expectations: {e}")
            return []
