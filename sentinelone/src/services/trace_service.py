"""SentinelOne Trace Service Provider."""

import logging
from datetime import UTC, datetime
from typing import Any

from ..collector.models import ExpectationResult, ExpectationTrace
from ..models.configs.config_loader import ConfigLoader
from .exception import SentinelOneDataConversionError, SentinelOneValidationError

LOG_PREFIX = "[SentinelOneTraceService]"


class SentinelOneTraceService:
    """SentinelOne-specific trace service provider.

    This service extracts trace information from expectation processing results
    and converts them into OpenAEV expectation traces using proper Pydantic models.
    """

    def __init__(self, config: ConfigLoader | None = None) -> None:
        """Initialize the SentinelOne trace service.

        Args:
            config: Configuration loader instance for trace service settings.

        Raises:
            SentinelOneValidationError: If config is None.

        """
        if config is None:
            raise SentinelOneValidationError("Config is required for trace service")

        self.logger = logging.getLogger(__name__)
        self.config = config
        self.logger.debug(f"{LOG_PREFIX} SentinelOne trace service initialized")

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
            SentinelOneValidationError: If inputs are invalid.
            SentinelOneDataConversionError: If trace creation fails.

        """
        if not collector_id:
            raise SentinelOneValidationError("collector_id cannot be empty")

        if not isinstance(results, list):
            raise SentinelOneValidationError("results must be a list")

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

                self.logger.debug(
                    f"{LOG_PREFIX} Creating trace {i}/{len(valid_results)} for expectation {expectation_id}"
                )

                try:
                    trace = self._create_expectation_trace(
                        result, expectation_id, collector_id
                    )

                    if trace:
                        traces.append(trace)
                        self.logger.debug(
                            f"{LOG_PREFIX} Created trace for expectation {expectation_id}: {trace.inject_expectation_trace_alert_name}"
                        )
                    else:
                        self.logger.warning(
                            f"{LOG_PREFIX} Trace creation returned None for expectation {expectation_id}"
                        )
                except Exception as e:
                    raise SentinelOneDataConversionError(
                        f"Error creating trace for expectation {expectation_id}: {e}"
                    ) from e

            self.logger.info(
                f"{LOG_PREFIX} Successfully created {len(traces)} traces from {len(valid_results)} valid results"
            )
            return traces

        except SentinelOneDataConversionError:
            raise
        except Exception as e:
            raise SentinelOneDataConversionError(
                f"Unexpected error creating traces from results: {e}"
            ) from e

    def _create_expectation_trace(
        self, result: ExpectationResult, expectation_id: str, collector_id: str
    ) -> ExpectationTrace:
        """Create ExpectationTrace model from a single result.

        Args:
            result: Processing result dictionary.
            expectation_id: ID of the expectation.
            collector_id: ID of the collector.

        Returns:
            ExpectationTrace model for OpenAEV.

        Raises:
            SentinelOneValidationError: If inputs are invalid.
            SentinelOneDataConversionError: If trace creation fails.

        """
        if not expectation_id:
            raise SentinelOneValidationError("expectation_id cannot be empty")

        if not collector_id:
            raise SentinelOneValidationError("collector_id cannot be empty")

        if not result.matched_alerts:
            raise SentinelOneValidationError(
                "result must have matched_alerts for trace creation"
            )

        try:
            matching_data = result.matched_alerts[0] or {}
            self.logger.debug(
                f"{LOG_PREFIX} Processing matching data with {len(matching_data)} fields"
            )

            alert_name = matching_data.get("alert_name", "SentinelOne Alert")

            trace_link = matching_data.get("alert_link", "")
            self.logger.debug(f"{LOG_PREFIX} Using trace builder URL: {trace_link}")

            trace_date = datetime.now(UTC).replace(microsecond=0)
            date_str = trace_date.isoformat() + "Z"
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

        except SentinelOneValidationError:
            raise
        except Exception as e:
            raise SentinelOneDataConversionError(
                f"Error creating expectation trace: {e}"
            ) from e

    def get_service_info(self) -> dict[str, Any]:
        """Get information about this trace service.

        Returns:
            Dictionary containing service metadata and capabilities.

        """
        info = {
            "service_type": "sentinelone_trace",
            "supported_result_types": ["SentinelOne processing results"],
            "creates_detection_traces": True,
            "creates_prevention_traces": True,
            "description": "Creates traces from SentinelOne expectation processing results using trace builder URLs",
        }
        self.logger.debug(f"{LOG_PREFIX} Trace service info: {info}")
        return info
