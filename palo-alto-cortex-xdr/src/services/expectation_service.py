"""PaloAltoCortexXDR Expectation Service with batch-based processing."""

import logging
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field
from pyoaev.apis.inject_expectation.model.expectation import (
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.signatures.types import SignatureTypes

from ..models.alert import Alert
from ..models.authentication import Authentication
from .alert_fetcher import AlertFetcher
from .client_api import PaloAltoCortexXDRClientAPI
from .converter import PaloAltoCortexXDRConverter
from .exception import (
    PaloAltoCortexXDRAPIError,
    PaloAltoCortexXDRExpectationError,
)
from .utils import SignatureExtractor, TraceBuilder

LOG_PREFIX = "[ExpectationService]"


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


class ExpectationService:
    """Service for processing PaloAltoCortexXDR expectations in batches."""

    def __init__(
        self,
        config: Any | None = None,
    ) -> None:
        """Initialize the PaloAltoCortexXDR expectation service.

        Args:
            config: Configuration loader for alternative initialization.

        Raises:
            PaloAltoCortexXDRValidationError: If required parameters are None.

        """
        self.logger: logging.Logger = logging.getLogger(__name__)

        auth = Authentication(
            api_key=config.palo_alto_cortex_xdr.api_key.get_secret_value(),
            api_key_id=config.palo_alto_cortex_xdr.api_key_id,
            auth_type=config.palo_alto_cortex_xdr.api_key_type,
        )
        self.client_api = PaloAltoCortexXDRClientAPI(
            auth=auth, fqdn=config.palo_alto_cortex_xdr.fqdn
        )
        self.converter: PaloAltoCortexXDRConverter = PaloAltoCortexXDRConverter()
        self.batch_size: int = config.palo_alto_cortex_xdr.expectation_batch_size

        self.time_window = config.palo_alto_cortex_xdr.time_window

        self.alert_fetcher: AlertFetcher = AlertFetcher(self.client_api)

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
    ) -> tuple[list[ExpectationResult], int]:
        """Handle a batch of expectations.

        Args:
            expectations: List of expectations to process.
            detection_helper: OpenAEV detection helper instance.

        Returns:
            Tuple of (results, skipped_count) where:
            - results: List of ExpectationResult objects for processed expectations
            - skipped_count: Number of expectations skipped due to missing end_date

        Raises:
            PaloAltoCortexXDRExpectationError: If batch processing fails.

        """
        if not expectations:
            self.logger.info(f"{LOG_PREFIX} No expectations to process")
            return [], 0

        try:
            self.logger.info(
                f"{LOG_PREFIX} Starting new batch processing of {len(expectations)} expectations"
            )

            batches, skipped_count = self._create_expectation_batches(expectations)
            self.logger.info(
                f"{LOG_PREFIX} Created {len(batches)} batches of size {self.batch_size} (skipped {skipped_count} expectations without end_date)"
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
                            PaloAltoCortexXDRExpectationError(
                                f"Batch processing error: {e}"
                            ),
                            expectation,
                        )
                        for expectation in batch
                    ]
                    all_results.extend(error_results)

            valid_count = sum(1 for r in all_results if r.is_valid)
            invalid_count = len(all_results) - valid_count

            self.logger.info(
                f"{LOG_PREFIX} New batch processing completed: {valid_count} valid, {invalid_count} invalid, {skipped_count} skipped (no end_date)"
            )

            return all_results, skipped_count

        except Exception as e:
            raise PaloAltoCortexXDRExpectationError(
                f"Error in handle_batch_expectations: {e}"
            ) from e

    def _create_expectation_batches(
        self, expectations: list[DetectionExpectation | PreventionExpectation]
    ) -> tuple[list[list[DetectionExpectation | PreventionExpectation]], int]:
        """Group expectations into batches, filtering out those without end_date.

        Args:
            expectations: List of expectations to batch.

        Returns:
            Tuple of (batches, skipped_count) where:
            - batches: List of expectation batches that have end_date signatures
            - skipped_count: Number of expectations skipped due to missing end_date

        """
        valid_expectations = []
        skipped_count = 0

        for expectation in expectations:
            has_end_date = (
                SignatureExtractor.extract_end_date([expectation]) is not None
            )

            if has_end_date:
                valid_expectations.append(expectation)
            else:
                skipped_count += 1
                self.logger.debug(
                    f"{LOG_PREFIX} Skipping expectation {expectation.inject_expectation_id} - no end_date signature found"
                )

        if skipped_count > 0:
            self.logger.info(
                f"{LOG_PREFIX} Filtered out {skipped_count} expectations without end_date signatures"
            )

        batches = []
        for i in range(0, len(valid_expectations), self.batch_size):
            batch = valid_expectations[i : i + self.batch_size]
            batches.append(batch)

        self.logger.debug(
            f"{LOG_PREFIX} Created {len(batches)} batches from {len(valid_expectations)} valid expectations (skipped {skipped_count})"
        )
        return batches, skipped_count

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
            alerts = self._fetch_alerts_for_time_window(batch)
            self.logger.info(
                f"{LOG_PREFIX} Batch {batch_idx}: Fetched {len(alerts)} alerts from time window"
            )

            self.logger.debug(
                f"{LOG_PREFIX} Batch {batch_idx}: Processing {len(alerts)} alerts"
            )

            results = self._match_alerts_to_expectations(
                batch, alerts, detection_helper
            )

            return results

        except Exception as e:
            raise PaloAltoCortexXDRExpectationError(
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

    def _fetch_alerts_for_time_window(
        self, batch: list[DetectionExpectation | PreventionExpectation] | None = None
    ) -> list[Alert]:
        """Fetch all alerts from the configured time window or date signatures.

        Args:
            batch: Optional batch of expectations to extract date filters from.

        Returns:
            List of Alert objects from the time window.

        Raises:
            PaloAltoCortexXDRAPIError: If API call fails.

        """
        try:
            end_time = self._extract_end_date_from_batch(batch)

            if end_time is None:
                end_time = datetime.now(timezone.utc)

            start_time = end_time - self.time_window

            self.logger.debug(
                f"{LOG_PREFIX} Delegating alert fetching to FetcherAlert for time window: {start_time} to {end_time}"
            )

            return self.alert_fetcher.fetch_alerts_for_time_window(
                start_time=start_time,
                end_time=end_time,
            )

        except Exception as e:
            raise PaloAltoCortexXDRAPIError(
                f"Error fetching alerts for time window: {e}"
            ) from e

    def _match_alerts_to_expectations(
        self,
        batch: list[DetectionExpectation | PreventionExpectation],
        alerts: list[Alert],
        detection_helper: Any,
    ) -> list[ExpectationResult]:
        """Match alerts and events to expectations and create results.

        Args:
            batch: Batch of expectations.
            alerts: List of filtered alerts.
            detection_helper: OpenAEV detection helper.

        Returns:
            List of ExpectationResult objects.

        """
        results = []

        for expectation in batch:
            try:
                matched = False
                traces = []

                for alert in alerts:
                    if self._expectation_matches_alert_data(
                        expectation, alert, detection_helper
                    ):
                        fqdn = self.client_api.fqdn
                        trace = TraceBuilder.create_alert_trace(alert, fqdn)
                        traces.append(trace)

                        if isinstance(expectation, PreventionExpectation):
                            if "Prevented" in alert.action_pretty:
                                matched = True
                                self.logger.debug(
                                    f"{LOG_PREFIX} Prevention expectation {expectation.inject_expectation_id}: "
                                    f"alert {alert.alert_id} matched signature and action is prevented -> expectation satisfied"
                                )
                                break
                            self.logger.debug(
                                f"{LOG_PREFIX} Prevention expectation {expectation.inject_expectation_id}: "
                                f"alert {alert.alert_id} matched signature but not prevented -> continuing search"
                            )
                        else:
                            if "Detected" in alert.action_pretty:
                                matched = True
                                self.logger.debug(
                                    f"{LOG_PREFIX} Detection expectation {expectation.inject_expectation_id}: "
                                    f"alert {alert.alert_id} matched signature -> expectation satisfied"
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
                    PaloAltoCortexXDRExpectationError(f"Matching error: {e}"),
                    expectation,
                )
                results.append(error_result)

        return results

    def _expectation_matches_alert_data(
        self,
        expectation: DetectionExpectation | PreventionExpectation,
        alert: Alert,
        detection_helper: Any,
    ) -> bool:
        """Check if an expectation matches the given alert and events using converter and detection helper.

        Args:
            expectation: The expectation to match.
            alert: The alert data.
            detection_helper: OpenAEV detection helper for matching.

        Returns:
            True if the expectation matches, False otherwise.

        """
        try:
            oaev_data_list = self.converter.convert_alerts_to_oaev([alert])

            if not oaev_data_list:
                self.logger.debug(
                    f"{LOG_PREFIX} No OAEV data generated for alert {alert.alert_id}"
                )
                return False

            oaev_data = oaev_data_list[0]

            parent_process_names = [alert.actor_process_command_line]
            oaev_implant_names = [
                name for name in parent_process_names if "oaev-implant-" in name
            ]

            self.logger.debug(
                f"{LOG_PREFIX} Alert {alert.alert_id}: Found {len(parent_process_names)} "
                f"process name, {len(oaev_implant_names)} with oaev-implant- prefix"
            )

            if oaev_implant_names:
                oaev_data["parent_process_name"] = {
                    "type": "simple",
                    "data": oaev_implant_names,
                    "score": 95,
                }
                self.logger.debug(
                    f"{LOG_PREFIX} Added execution parent processes to OAEV for {alert.alert_id}: {oaev_implant_names}"
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
                filtered_data = (
                    {sig_type: filtered_oaev_data[sig_type]}
                    if sig_type in filtered_oaev_data
                    else {}
                )
                self.logger.debug(
                    f"{LOG_PREFIX} Detection helper input - sig_type: {sig_type}"
                )
                self.logger.debug(
                    f"{LOG_PREFIX} Detection helper input - signatures: {signatures}"
                )
                self.logger.debug(
                    f"{LOG_PREFIX} Detection helper input - filtered_data: {filtered_data}"
                )

                match_result = detection_helper.match_alert_elements(
                    signatures, filtered_data
                )

                self.logger.debug(
                    f"{LOG_PREFIX} Detection helper result for {sig_type}: {match_result}"
                )

                if not match_result:
                    self.logger.debug(
                        f"{LOG_PREFIX} {sig_type} signature failed for alert {alert.alert_id}"
                    )
                    return False

            self.logger.debug(
                f"{LOG_PREFIX} All signatures matched for expectation {expectation.inject_expectation_id} vs alert {alert.alert_id}"
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
            "service_name": "PaloAltoCortexXDRExpectationService",
            "batch_size": self.batch_size,
            "supported_signatures": self.get_supported_signatures(),
            "flow_type": "batch_based",
        }
