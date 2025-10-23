"""SentinelOne Expectation Service with batch-based processing."""

import logging
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field
from pyoaev.apis.inject_expectation.model.expectation import (
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.signatures.types import SignatureTypes

from .client_api import SentinelOneClientAPI
from .converter import SentinelOneConverter
from .exception import (
    SentinelOneAPIError,
    SentinelOneExpectationError,
)
from .fetcher_threat import FetcherThreat
from .fetcher_threat_events import FetcherThreatEvents
from .model_threat import SentinelOneThreat
from .utils import SignatureExtractor, TraceBuilder

LOG_PREFIX = "[SentinelOneExpectationService]"


class ExpectationResult(BaseModel):
    """Model for expectation processing results."""

    expectation_id: str = Field(..., description="ID of the processed expectation")
    is_valid: bool = Field(..., description="Whether the expectation was validated")
    expectation: Any | None = Field(None, description="The original expectation object")
    matched_alerts: list[dict[str, Any]] | None = Field(
        None, description="List of alerts that matched this expectation"
    )
    error_message: str | None = Field(
        None, description="Error message if processing failed"
    )
    processing_time: float | None = Field(
        None, description="Time taken to process this expectation in seconds"
    )


class SentinelOneExpectationService:
    """Service for processing SentinelOne expectations in batches."""

    def __init__(
        self,
        config: Any | None = None,
    ) -> None:
        """Initialize the SentinelOne expectation service.

        Args:
            config: Configuration loader for alternative initialization.

        Raises:
            SentinelOneValidationError: If required parameters are None.

        """
        self.logger: logging.Logger = logging.getLogger(__name__)

        self.client_api: SentinelOneClientAPI = SentinelOneClientAPI(config)
        self.converter: SentinelOneConverter = SentinelOneConverter()
        self.batch_size: int = config.sentinelone.expectation_batch_size

        self.threat_fetcher: FetcherThreat = FetcherThreat(self.client_api)
        self.threat_events_fetcher: FetcherThreatEvents = FetcherThreatEvents(
            self.client_api
        )

        self.logger.info(
            f"{LOG_PREFIX} Service initialized with batch size: {self.batch_size}"
        )

    def get_supported_signatures(self) -> list[SignatureTypes]:
        """Get list of supported signature types.

        Returns:
            List of supported SignatureTypes enum values.

        """
        return [
            SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
            SignatureTypes.SIG_TYPE_TARGET_HOSTNAME_ADDRESS,
            SignatureTypes.SIG_TYPE_END_DATE,
        ]

    def handle_batch_expectations(
        self,
        expectations: list[DetectionExpectation | PreventionExpectation],
        detection_helper: Any,
    ) -> list[ExpectationResult]:
        """Handle a batch of expectations.

        Args:
            expectations: List of expectations to process.
            detection_helper: OpenAEV detection helper instance.

        Returns:
            List of ExpectationResult objects.

        Raises:
            SentinelOneExpectationError: If batch processing fails.

        """
        if not expectations:
            self.logger.info(f"{LOG_PREFIX} No expectations to process")
            return []

        try:
            self.logger.info(
                f"{LOG_PREFIX} Starting new batch processing of {len(expectations)} expectations"
            )

            batches = self._create_expectation_batches(expectations)
            self.logger.info(
                f"{LOG_PREFIX} Created {len(batches)} batches of size {self.batch_size}"
            )

            all_results = []

            for batch_idx, batch in enumerate(batches, 1):
                self.logger.info(
                    f"{LOG_PREFIX} Processing batch {batch_idx}/{len(batches)} with {len(batch)} expectations"
                )

                try:
                    batch_results = self._process_expectation_batch(
                        batch, detection_helper, batch_idx
                    )
                    all_results.extend(batch_results)

                    self.logger.info(
                        f"{LOG_PREFIX} Batch {batch_idx} completed: {len(batch_results)} results"
                    )
                except Exception as e:
                    self.logger.error(
                        f"{LOG_PREFIX} Error processing batch {batch_idx}: {e}"
                    )
                    error_results = [
                        self._create_error_result_object(
                            SentinelOneExpectationError(f"Batch processing error: {e}"),
                            expectation,
                        )
                        for expectation in batch
                    ]
                    all_results.extend(error_results)

            valid_count = sum(1 for r in all_results if r.is_valid)
            invalid_count = len(all_results) - valid_count

            self.logger.info(
                f"{LOG_PREFIX} New batch processing completed: {valid_count} valid, {invalid_count} invalid"
            )

            return all_results

        except Exception as e:
            raise SentinelOneExpectationError(
                f"Error in handle_batch_expectations: {e}"
            ) from e

    def _create_expectation_batches(
        self, expectations: list[DetectionExpectation | PreventionExpectation]
    ) -> list[list[DetectionExpectation | PreventionExpectation]]:
        """Group expectations into batches.

        Args:
            expectations: List of expectations to batch.

        Returns:
            List of expectation batches.

        """
        batches = []
        for i in range(0, len(expectations), self.batch_size):
            batch = expectations[i : i + self.batch_size]
            batches.append(batch)

        self.logger.debug(
            f"{LOG_PREFIX} Created {len(batches)} batches from {len(expectations)} expectations"
        )
        return batches

    def _process_expectation_batch(
        self,
        batch: list[DetectionExpectation | PreventionExpectation],
        detection_helper: Any,
        batch_idx: int,
    ) -> list[ExpectationResult]:
        """Process a single batch of expectations.

        Args:
            batch: Batch of expectations to process.
            detection_helper: OpenAEV detection helper.
            batch_idx: Batch index for logging.

        Returns:
            List of ExpectationResult objects for this batch.

        """
        try:
            process_names = self._extract_process_names_from_batch(batch)

            self.logger.debug(
                f"{LOG_PREFIX} Batch {batch_idx}: Found {len(process_names)} unique process names"
            )

            threats = self._fetch_threats_for_time_window(batch)
            self.logger.info(
                f"{LOG_PREFIX} Batch {batch_idx}: Fetched {len(threats)} threats from time window"
            )

            static_threats = [threat for threat in threats if threat.is_static]
            non_static_threats = [threat for threat in threats if not threat.is_static]

            self.logger.debug(
                f"{LOG_PREFIX} Batch {batch_idx}: Processing {len(static_threats)} static threats "
                f"and {len(non_static_threats)} non-static threats"
            )

            threat_events = {}
            for threat in non_static_threats:
                events = self.threat_events_fetcher.fetch_events_for_threat(
                    threat, process_names
                )
                if events:
                    threat_events[threat.threat_id] = events
                    self.logger.debug(
                        f"{LOG_PREFIX} Batch {batch_idx}: Non-static threat {threat.threat_id} has {len(events)} matching events"
                    )

            for threat in static_threats:
                # TODO
                self.logger.debug(
                    f"{LOG_PREFIX} Batch {batch_idx}: Static threat {threat.threat_id} - no events to fetch"
                )

            results = self._match_threats_to_expectations(
                batch, threats, threat_events, detection_helper
            )

            return results

        except Exception as e:
            raise SentinelOneExpectationError(
                f"Error processing batch {batch_idx}: {e}"
            ) from e

    def _extract_hostnames_from_batch(
        self, batch: list[DetectionExpectation | PreventionExpectation]
    ) -> list[str]:
        """Extract unique hostnames from a batch of expectations.

        Args:
            batch: Batch of expectations.

        Returns:
            List of unique hostnames.

        """
        return SignatureExtractor.extract_hostnames(batch)

    def _extract_process_names_from_batch(
        self, batch: list[DetectionExpectation | PreventionExpectation]
    ) -> list[str]:
        """Extract unique parent process names from a batch of expectations.

        Args:
            batch: Batch of expectations.

        Returns:
            List of unique parent process names.

        """
        return SignatureExtractor.extract_process_names(batch)

    def _extract_end_date_from_batch(
        self, batch: list[DetectionExpectation | PreventionExpectation] | None = None
    ) -> datetime | None:
        """Extract end_date from batch signatures.

        Args:
            batch: Batch of expectations to extract end_date from.

        Returns:
            end_date as datetime or None if no end_date signature found.

        """
        end_date = SignatureExtractor.extract_end_date(batch)
        if end_date:
            self.logger.debug(
                f"{LOG_PREFIX} Extracted end_date from signatures: {end_date}, start_date will be calculated from time_window"
            )
        return end_date

    def _fetch_threats_for_time_window(
        self, batch: list[DetectionExpectation | PreventionExpectation] | None = None
    ) -> list[SentinelOneThreat]:
        """Fetch all threats from the configured time window or date signatures.

        Args:
            batch: Optional batch of expectations to extract date filters from.

        Returns:
            List of SentinelOneThreat objects from the time window.

        Raises:
            SentinelOneAPIError: If API call fails.

        """
        try:
            end_time = self._extract_end_date_from_batch(batch)

            if end_time is None:
                end_time = datetime.now(timezone.utc)

            start_time = end_time - self.client_api.time_window

            self.logger.debug(
                f"{LOG_PREFIX} Delegating threat fetching to FetcherThreat for time window: {start_time} to {end_time}"
            )

            # Use the dedicated threat fetcher with hostname filtering
            return self.threat_fetcher.fetch_threats_for_time_window(
                start_time=start_time,
                end_time=end_time,
                limit=1000,
            )

        except Exception as e:
            raise SentinelOneAPIError(
                f"Error fetching threats for time window: {e}"
            ) from e

    def _match_threats_to_expectations(
        self,
        batch: list[DetectionExpectation | PreventionExpectation],
        threats: list[SentinelOneThreat],
        threat_events: dict[str, list[dict[str, Any]]],
        detection_helper: Any,
    ) -> list[ExpectationResult]:
        """Match threats and events to expectations and create results.

        Args:
            batch: Batch of expectations.
            threats: List of filtered threats.
            threat_events: Dictionary mapping threat IDs to their events.
            detection_helper: OpenAEV detection helper.

        Returns:
            List of ExpectationResult objects.

        """
        results = []

        for expectation in batch:
            try:
                matched = False
                traces = []

                for threat in threats:
                    events = threat_events.get(threat.threat_id, [])

                    if self._expectation_matches_threat_data(
                        expectation, threat, events, detection_helper
                    ):
                        base_url = self.client_api.base_url if self.client_api else ""
                        trace = TraceBuilder.create_threat_trace(
                            threat, base_url, events
                        )
                        traces.append(trace)

                        if isinstance(expectation, PreventionExpectation):
                            # breakpoint()
                            if threat.is_mitigated:
                                matched = True
                                self.logger.debug(
                                    f"{LOG_PREFIX} Prevention expectation {expectation.inject_expectation_id}: "
                                    f"threat {threat.threat_id} matched signature and is mitigated -> expectation satisfied"
                                )
                                break
                            self.logger.debug(
                                f"{LOG_PREFIX} Prevention expectation {expectation.inject_expectation_id}: "
                                f"threat {threat.threat_id} matched signature but not mitigated -> continuing search"
                            )
                        else:
                            matched = True
                            self.logger.debug(
                                f"{LOG_PREFIX} Detection expectation {expectation.inject_expectation_id}: "
                                f"threat {threat.threat_id} matched signature -> expectation satisfied"
                            )
                            break

                result_dict = {
                    "is_valid": matched,
                    "traces": traces,
                    "expectation_type": (
                        "detection"
                        if isinstance(expectation, DetectionExpectation)
                        else "prevention"
                    ),
                }

                result = self._convert_dict_to_result(result_dict, expectation)
                results.append(result)

                self.logger.debug(
                    f"{LOG_PREFIX} Expectation {expectation.inject_expectation_id}: "
                    f"matched={matched}, traces={len(traces)}"
                )

            except Exception as e:
                self.logger.error(
                    f"{LOG_PREFIX} Error matching expectation {expectation.inject_expectation_id}: {e}"
                )
                error_result = self._create_error_result_object(
                    SentinelOneExpectationError(f"Matching error: {e}"), expectation
                )
                results.append(error_result)

        return results

    def _expectation_matches_threat_data(
        self,
        expectation: DetectionExpectation | PreventionExpectation,
        threat: SentinelOneThreat,
        events: list[dict[str, Any]],
        detection_helper: Any,
    ) -> bool:
        """Check if an expectation matches the given threat and events using converter and detection helper.

        Args:
            expectation: The expectation to match.
            threat: The threat data.
            events: List of events for the threat.
            detection_helper: OpenAEV detection helper for matching.

        Returns:
            True if the expectation matches, False otherwise.

        """
        try:
            oaev_data_list = self.converter.convert_threats_to_oaev([threat])

            if not oaev_data_list:
                self.logger.debug(
                    f"{LOG_PREFIX} No OAEV data generated for threat {threat.threat_id}"
                )
                return False

            oaev_data = oaev_data_list[0]

            if events and not threat.is_static:
                parent_process_names = (
                    SentinelOneThreat.get_parent_process_name_from_events(events)
                )
                oaev_implant_names = [
                    name
                    for name in parent_process_names
                    if name.startswith("oaev-implant-")
                ]

                self.logger.debug(
                    f"{LOG_PREFIX} Threat {threat.threat_id}: Found {len(parent_process_names)} "
                    f"parent process names, {len(oaev_implant_names)} with oaev-implant- prefix"
                )

                if oaev_implant_names:
                    # breakpoint()
                    oaev_data["parent_process_name"] = {
                        "type": "fuzzy",
                        "data": oaev_implant_names,
                        "score": 95,
                    }
                    self.logger.debug(
                        f"{LOG_PREFIX} Added oaev-implant parent processes to OAEV: {oaev_implant_names}"
                    )

            supported_signatures = self.get_supported_signatures()
            self.logger.debug(
                f"{LOG_PREFIX} Supported signature types: {[s.value for s in supported_signatures]}"
            )

            signature_groups = SignatureExtractor.group_signatures_by_type(
                expectation, supported_signatures
            )
            self.logger.debug(
                f"{LOG_PREFIX} Filtered signature groups: {list(signature_groups.keys())}"
            )

            supported_sig_names = {
                sig_type.value if hasattr(sig_type, "value") else str(sig_type)
                for sig_type in supported_signatures
            }
            filtered_oaev_data = {
                key: value
                for key, value in oaev_data.items()
                if key in supported_sig_names
            }
            self.logger.debug(
                f"{LOG_PREFIX} Available OAEV data: {list(oaev_data.keys())}"
            )
            self.logger.debug(
                f"{LOG_PREFIX} Filtered OAEV data: {list(filtered_oaev_data.keys())}"
            )

            for sig_type, signatures in signature_groups.items():
                filtered_data = {sig_type: filtered_oaev_data[sig_type]}
                self.logger.debug(
                    f"{LOG_PREFIX} Detection helper input - sig_type: {sig_type}"
                )
                self.logger.debug(
                    f"{LOG_PREFIX} Detection helper input - signatures: {signatures}"
                )
                self.logger.debug(
                    f"{LOG_PREFIX} Detection helper input - filtered_data: {filtered_data}"
                )

                # breakpoint()
                match_result = detection_helper.match_alert_elements(
                    signatures, filtered_data
                )

                self.logger.debug(
                    f"{LOG_PREFIX} Detection helper result for {sig_type}: {match_result}"
                )

                if not match_result:
                    self.logger.debug(
                        f"{LOG_PREFIX} {sig_type} signature failed for threat {threat.threat_id}"
                    )
                    return False

            self.logger.debug(
                f"{LOG_PREFIX} All signatures matched for expectation {expectation.inject_expectation_id} vs threat {threat.threat_id}"
            )
            return True

        except Exception as e:
            self.logger.warning(f"{LOG_PREFIX} Error in expectation matching: {e}")
            return False

    def _create_error_result_object(
        self,
        error: Exception,
        expectation: DetectionExpectation | PreventionExpectation,
    ) -> ExpectationResult:
        """Create an error result object.

        Args:
            error: The error that occurred.
            expectation: The expectation that failed.

        Returns:
            ExpectationResult object representing the error.

        """
        return ExpectationResult(
            expectation_id=str(expectation.inject_expectation_id),
            is_valid=False,
            expectation=expectation,
            matched_alerts=None,
            error_message=str(error),
            processing_time=None,
        )

    def _convert_dict_to_result(
        self,
        result_dict: dict[str, Any],
        expectation: DetectionExpectation | PreventionExpectation,
    ) -> ExpectationResult:
        """Convert result dictionary to ExpectationResult object.

        Args:
            result_dict: Dictionary containing result data.
            expectation: The associated expectation.

        Returns:
            ExpectationResult object.

        """
        return ExpectationResult(
            expectation_id=str(expectation.inject_expectation_id),
            is_valid=result_dict.get("is_valid", False),
            expectation=expectation,
            matched_alerts=result_dict.get("traces", []),
            error_message=result_dict.get("error"),
            processing_time=None,
        )

    def get_service_info(self) -> dict[str, Any]:
        """Get service information.

        Returns:
            Dictionary containing service information.

        """
        return {
            "service_name": "SentinelOneExpectationService",
            "batch_size": self.batch_size,
            "supported_signatures": self.get_supported_signatures(),
            "flow_type": "batch_based",
        }
