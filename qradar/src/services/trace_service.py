"""IBM QRadar Trace Service Provider.

This module provides IBM QRadar-specific logic for creating expectation traces
from processing results.
"""

import logging
from datetime import datetime
from typing import Any
from urllib.parse import quote

from pyoaev.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    DetectionExpectation,
    PreventionExpectation,
)

from ..collector.models import ExpectationResult, ExpectationTrace
from ..models.configs.config_loader import ConfigLoader
from .client_api import QRadarClientAPI
from .exception import QRadarDataConversionError, QRadarValidationError

LOG_PREFIX = "[QRadarTraceService]"


class QRadarTraceService:
    """IBM QRadar-specific trace service provider.

    This service extracts trace information from expectation processing results
    and converts them into OpenAEV expectation traces using proper Pydantic models.
    """

    def __init__(self, config: ConfigLoader | None = None) -> None:
        """Initialize the IBM QRadar trace service.

        Args:
            config: Configuration loader instance for trace service settings.

        Raises:
            QRadarValidationError: If config is None.

        """
        if config is None:
            raise QRadarValidationError("Config is required for trace service")

        self.logger = logging.getLogger(__name__)
        self.config = config
        self.client_api = QRadarClientAPI(config)
        self.logger.debug(f"{LOG_PREFIX} IBM QRadar trace service initialized")

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
            QRadarValidationError: If inputs are invalid.
            QRadarDataConversionError: If trace creation fails.

        """
        if not collector_id:
            raise QRadarValidationError("collector_id cannot be empty")

        if not isinstance(results, list):
            raise QRadarValidationError("results must be a list")

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
                    raise QRadarDataConversionError(
                        f"Error creating trace for expectation {expectation_id}: {e}"
                    ) from e

            self.logger.info(
                f"{LOG_PREFIX} Successfully created {len(traces)} traces from {len(valid_results)} valid results"
            )
            return traces

        except QRadarDataConversionError:
            raise
        except Exception as e:
            raise QRadarDataConversionError(
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
            QRadarValidationError: If inputs are invalid.
            QRadarDataConversionError: If trace creation fails.

        """
        if not expectation_id:
            raise QRadarValidationError("expectation_id cannot be empty")

        if not collector_id:
            raise QRadarValidationError("collector_id cannot be empty")

        if not result.matched_alerts:
            raise QRadarValidationError(
                "result must have matched_alerts for trace creation"
            )

        try:
            matching_data = result.matched_alerts[0] or {}
            self.logger.debug(
                f"{LOG_PREFIX} Processing matching data with {len(matching_data)} fields"
            )

            alert_name = self._determine_alert_name(matching_data)

            self.logger.debug(f"{LOG_PREFIX} Building trace URL from matching data...")
            trace_link = self._build_trace_url_from_expectation(result.expectation)
            self.logger.debug(f"{LOG_PREFIX} Generated trace link: {trace_link}")

            trace_date = datetime.utcnow().replace(microsecond=0)
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

        except QRadarValidationError:
            raise
        except Exception as e:
            raise QRadarDataConversionError(
                f"Error creating expectation trace: {e}"
            ) from e

    def _determine_alert_name(self, matching_data: dict[str, Any]) -> str:
        """Determine alert name based on matching data content.

        Args:
            matching_data: Dictionary containing the matched data elements.

        Returns:
            Human-readable alert name based on data content.

        """
        self.logger.debug(f"{LOG_PREFIX} Creating trace for IBM QRadar alert")
        self.logger.debug(
            f"{LOG_PREFIX} Creating trace from matching data {matching_data}"
        )

        if (
            "source_ipv4_address" in matching_data
            or "source_ipv6_address" in matching_data
        ):
            self.logger.debug(
                f"{LOG_PREFIX} Creating trace for detection event (source IP)"
            )
            return "IBM QRadar Detection Alert - Source IP"
        elif (
            "target_ipv4_address" in matching_data
            or "target_ipv6_address" in matching_data
        ):
            self.logger.debug(
                f"{LOG_PREFIX} Creating trace for detection event (target IP)"
            )
            return "IBM QRadar Detection Alert - Target IP"
        else:
            self.logger.debug(
                f"{LOG_PREFIX} Using generic alert name - no specific IP data type identified"
            )
            return "IBM QRadar Detection Alert"

    def _build_trace_url_from_expectation(
        self, expectation: DetectionExpectation | PreventionExpectation
    ) -> str:
        """Build a QRadar Log Activity URL from the expectation signatures.

        Reuses ``client_api._build_search_criteria`` to extract the source and
        destination IPs from the expectation signatures, then builds a Log
        Activity filter from those IPs only. Unlike the AQL query built by
        ``client_api._build_aql``, this URL does not include the parent-process
        ``URL`` match or the search time window.

        Args:
            expectation: The expectation object with signatures.

        Returns:
            QRadar Log Activity URL filtered by the expectation's source and
            destination IPs.

        Raises:
            QRadarDataConversionError: If URL building fails.

        """
        try:
            if not hasattr(self.config, "qradar"):
                self.logger.warning(
                    f"{LOG_PREFIX} No IBM QRadar config available, returning empty URL"
                )
                return ""

            console_url = getattr(self.config.qradar, "console_url", None)
            if console_url:
                web_base_url = str(console_url).rstrip("/")
            else:
                web_base_url = str(self.config.qradar.base_url).rstrip("/")
            self.logger.debug(f"{LOG_PREFIX} Using QRadar console URL: {web_base_url}")

            search_signatures = []
            for sig in expectation.inject_expectation_signatures:
                search_signatures.append({"type": sig.type.value, "value": sig.value})

            search_criteria = self.client_api._build_search_criteria(search_signatures)
            filter_parts = []
            for ip in search_criteria.source_ips or []:
                filter_parts.append(f"sourceip={ip}")
            for ip in search_criteria.target_ips or []:
                filter_parts.append(f"destinationip={ip}")
            filter_query = " ".join(filter_parts)

            encoded_query = quote(filter_query)
            url = (
                f"{web_base_url}/console/qradar/jsp/QRadar.jsp"
                f"?appName=Sem&pageId=LogActivity&filter={encoded_query}"
            )

            self.logger.debug(
                f"{LOG_PREFIX} Built trace URL with filter: {filter_query}"
            )
            return url

        except Exception as e:
            raise QRadarDataConversionError(f"Error building trace URL: {e}") from e

    def get_service_info(self) -> dict[str, Any]:
        """Get information about this trace service.

        Returns:
            Dictionary containing service metadata and capabilities.

        """
        info = {
            "service_type": "qradar_trace",
            "supported_result_types": ["IBM QRadar processing results"],
            "creates_detection_traces": True,
            "creates_prevention_traces": False,
            "description": "Creates traces from IBM QRadar expectation processing results",
        }
        self.logger.debug(f"{LOG_PREFIX} Trace service info: {info}")
        return info
