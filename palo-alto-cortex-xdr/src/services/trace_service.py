"""PaloAltoCortexXDR Trace Service Provider."""

import logging
from datetime import UTC, datetime
from typing import Any

from src.collector.models import ExpectationResult, ExpectationTrace
from src.models.settings.config_loader import ConfigLoader
from src.services.exception import (
    PaloAltoCortexXDRDataConversionError,
    PaloAltoCortexXDRValidationError,
)

LOG_PREFIX = "[TraceService]"


class TraceService:
    """PaloAltoCortexXDR-specific trace service provider.

    This service extracts trace information from expectation processing results
    and converts them into OpenAEV expectation traces using proper Pydantic models.
    """

    def __init__(self, config: ConfigLoader | None = None) -> None:
        if config is None:
            raise PaloAltoCortexXDRValidationError(
                "Config is required for trace service"
            )

        self.logger = logging.getLogger(__name__)
        self.config = config
        self.logger.debug(f"{LOG_PREFIX} PaloAltoCortexXDR trace service initialized")

    def create_traces_from_results(
        self, results: list[ExpectationResult], collector_id: str
    ) -> list[ExpectationTrace]:
        """Create trace data from processing results.

        Args:
            results: List of expectation processing results.
            collector_id: ID of the collector.

        Returns:
            List of ExpectationTrace models for OpenAEV.

        Raises:
            PaloAltoCortexXDRValidationError: If inputs are invalid.
            PaloAltoCortexXDRDataConversionError: If trace creation fails.

        """
        if not collector_id:
            raise PaloAltoCortexXDRValidationError("collector_id cannot be empty")

        if not isinstance(results, list):
            raise PaloAltoCortexXDRValidationError("results must be a list")

        try:
            valid_results = [r for r in results if r.is_valid and r.matched_alerts]

            if not valid_results:
                self.logger.info(
                    f"{LOG_PREFIX} No valid results with matching data for traces out of {len(results)} results"
                )
                return []

            self.logger.info(
                f"{LOG_PREFIX} Creating traces for {len(valid_results)} valid results out of {len(results)} total"
            )

            traces = []
            for i, result in enumerate(valid_results, 1):
                expectation_id = result.expectation_id
                if not expectation_id:
                    self.logger.warning(
                        f"{LOG_PREFIX} Skipping result {i} - missing expectation_id"
                    )
                    continue

                for alert_data in result.matched_alerts:
                    try:
                        trace = self._create_expectation_trace(
                            alert_data, expectation_id, collector_id
                        )
                        if trace:
                            traces.append(trace)
                    except Exception as e:
                        self.logger.error(
                            f"{LOG_PREFIX} Error creating trace for expectation {expectation_id}: {e}"
                        )

            self.logger.info(
                f"{LOG_PREFIX} Successfully created {len(traces)} traces from {len(valid_results)} valid results"
            )
            return traces

        except PaloAltoCortexXDRDataConversionError:
            raise
        except Exception as e:
            raise PaloAltoCortexXDRDataConversionError(
                f"Unexpected error creating traces from results: {e}"
            ) from e

    def _create_expectation_trace(
        self, matching_data: dict[str, Any], expectation_id: str, collector_id: str
    ) -> ExpectationTrace:
        """Create ExpectationTrace model from a single result.

        Args:
            matching_data: Single alert matching data.
            expectation_id: ID of the expectation.
            collector_id: ID of the collector.

        Returns:
            ExpectationTrace model for OpenAEV.

        Raises:
            PaloAltoCortexXDRValidationError: If inputs are invalid.
            PaloAltoCortexXDRDataConversionError: If trace creation fails.

        """
        if not expectation_id:
            raise PaloAltoCortexXDRValidationError("expectation_id cannot be empty")

        if not collector_id:
            raise PaloAltoCortexXDRValidationError("collector_id cannot be empty")

        if not matching_data:
            raise PaloAltoCortexXDRValidationError(
                "matching_data cannot be empty for trace creation"
            )

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Processing matching data with {len(matching_data)} fields"
            )

            alert_name = matching_data.get("alert_name", "PaloAltoCortexXDR Alert")

            trace_link = matching_data.get("alert_link", "")
            self.logger.debug(f"{LOG_PREFIX} Using trace builder URL: {trace_link}")

            trace_date = datetime.now(UTC).replace(microsecond=0)
            date_str = trace_date.isoformat().replace("+00:00", "Z")
            self.logger.debug(f"{LOG_PREFIX} Generated trace date: {date_str}")

            trace = ExpectationTrace(
                inject_expectation_trace_expectation=str(expectation_id),
                inject_expectation_trace_source_id=str(collector_id),
                inject_expectation_trace_alert_name=alert_name,
                inject_expectation_trace_alert_link=trace_link,
                inject_expectation_trace_date=date_str,
            )

            self.logger.debug(
                f"{LOG_PREFIX} Created ExpectationTrace with alert name: {alert_name}"
            )
            return trace

        except PaloAltoCortexXDRValidationError:
            raise
        except Exception as e:
            raise PaloAltoCortexXDRDataConversionError(
                f"Error creating expectation trace: {e}"
            ) from e
