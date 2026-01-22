"""PaloAltoCortexXDR Expectation Service with batch-based processing."""

import logging
from datetime import datetime, timezone
from typing import Any

from pyoaev.apis.inject_expectation.model.expectation import (
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.signatures.types import SignatureTypes
from src.collector.models import ExpectationResult
from src.models.alert import Alert
from src.models.authentication import Authentication
from src.models.settings.config_loader import ConfigLoader

from .alert_fetcher import AlertFetcher
from .client_api import PaloAltoCortexXDRClientAPI
from .converter import PaloAltoCortexXDRConverter
from .exception import (
    PaloAltoCortexXDRAPIError,
    PaloAltoCortexXDRExpectationError,
    PaloAltoCortexXDRValidationError,
)
from .utils import SignatureExtractor, TraceBuilder

LOG_PREFIX = "[ExpectationService]"


class ExpectationService:
    """Service for processing PaloAltoCortexXDR expectations."""

    def __init__(
        self,
        config: ConfigLoader,
    ) -> None:
        """Initialize the PaloAltoCortexXDR expectation service.

        Args:
            config: Configuration loader for alternative initialization.

        Raises:
            PaloAltoCortexXDRValidationError: If required parameters are None.

        """
        self.logger: logging.Logger = logging.getLogger(__name__)

        if config is None:
            raise PaloAltoCortexXDRValidationError("config cannot be None")

        if config.palo_alto_cortex_xdr.fqdn is None:
            raise PaloAltoCortexXDRValidationError(
                "palo_alto_cortex_xdr.fqdn cannot be None"
            )

        auth = Authentication(
            api_key=config.palo_alto_cortex_xdr.api_key.get_secret_value(),
            api_key_id=config.palo_alto_cortex_xdr.api_key_id,
            auth_type=config.palo_alto_cortex_xdr.api_key_type,
        )
        self.client_api = PaloAltoCortexXDRClientAPI(
            auth=auth, fqdn=config.palo_alto_cortex_xdr.fqdn
        )
        self.converter: PaloAltoCortexXDRConverter = PaloAltoCortexXDRConverter()

        self.time_window = config.palo_alto_cortex_xdr.time_window

        self.alert_fetcher: AlertFetcher = AlertFetcher(self.client_api)

        self.logger.info(f"{LOG_PREFIX} Service initialized")

    def get_supported_signatures(self) -> list[SignatureTypes]:
        return [
            SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
            SignatureTypes.SIG_TYPE_TARGET_HOSTNAME_ADDRESS,
            SignatureTypes.SIG_TYPE_END_DATE,
        ]

    def handle_expectations(
        self,
        expectations: list[DetectionExpectation | PreventionExpectation],
        detection_helper: Any,
    ) -> list[ExpectationResult]:
        """Handle expectations.

        Args:
            expectations: List of expectations to process.
            detection_helper: OpenAEV detection helper instance.

        Returns:
            List of ExpectationResult objects for processed expectations

        Raises:
            PaloAltoCortexXDRExpectationError: If processing fails.

        """
        if not expectations:
            self.logger.info(f"{LOG_PREFIX} No expectations to process")
            return []

        try:
            self.logger.info(
                f"{LOG_PREFIX} Starting processing of {len(expectations)} expectations"
            )

            alerts = self._fetch_alerts_for_time_window(expectations)
            self.logger.info(
                f"{LOG_PREFIX} Fetched {len(alerts)} alerts from time window"
            )

            results = self._match_alerts_to_expectations(
                expectations, alerts, detection_helper
            )

            valid_count = sum(1 for r in results if r.is_valid)
            invalid_count = len(results) - valid_count

            self.logger.info(
                f"{LOG_PREFIX} Processing completed: {valid_count} valid, {invalid_count} invalid"
            )

            return results

        except Exception as e:
            raise PaloAltoCortexXDRExpectationError(
                f"Error in handle_expectations: {e}"
            ) from e

    def _extract_end_date_from_expectations(
        self,
        expectations: list[DetectionExpectation | PreventionExpectation] | None = None,
    ) -> datetime | None:
        """Extract end_date from expectation signatures.

        Args:
            expectations: List of expectations to extract end_date from.

        Returns:
            end_date as datetime or None if no end_date signature found.

        """
        end_date = SignatureExtractor.extract_end_date(expectations)
        if end_date:
            self.logger.debug(
                f"{LOG_PREFIX} Extracted end_date from signatures: {end_date}, start_date will be calculated from time_window"
            )
        return end_date

    def _fetch_alerts_for_time_window(
        self,
        expectations: list[DetectionExpectation | PreventionExpectation] | None = None,
    ) -> list[Alert]:
        """Fetch all alerts from the configured time window or date signatures.

        Args:
            expectations: Optional list of expectations to extract date filters from.

        Returns:
            List of Alert objects from the time window.

        Raises:
            PaloAltoCortexXDRAPIError: If API call fails.

        """
        try:
            end_time = self._extract_end_date_from_expectations(expectations)

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
                name
                for name in parent_process_names
                if name and "oaev-implant-" in name
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
            "supported_signatures": self.get_supported_signatures(),
            "flow_type": "all_at_once",
        }
