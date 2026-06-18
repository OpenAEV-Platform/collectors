import logging
from datetime import datetime, timezone
from typing import Any, List

from pyoaev.apis.inject_expectation.model.expectation import (
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.signatures.types import SignatureTypes
from src.collector.models import ExpectationResult
from src.models.authentication import Authentication
from src.models.settings.config_loader import ConfigLoader
from src.services.alert_fetcher import AlertFetcher
from src.services.client_api import PaloAltoCortexXSOARClientAPI
from src.services.converter import PaloAltoCortexXSOARConverter
from src.services.exception import (
    PaloAltoCortexXSOARAPIError,
    PaloAltoCortexXSOARExpectationError,
    PaloAltoCortexXSOARValidationError,
)
from src.services.ioc_extractor import IncidentResult

from .utils import SignatureExtractor, TraceBuilder

LOG_PREFIX = "[ExpectationService]"


class ExpectationService:
    """Service for processing PaloAltoCortexXSOAR expectations."""

    def __init__(
        self,
        config: ConfigLoader,
    ) -> None:
        """Initialize the PaloAltoCortexXSOAR expectation service.

        Args:
            config: Configuration loader for alternative initialization.

        Raises:
            PaloAltoCortexXSOARValidationError: If required parameters are None.

        """
        self.logger: logging.Logger = logging.getLogger(__name__)

        if config is None:
            raise PaloAltoCortexXSOARValidationError("config cannot be None")

        if config.palo_alto_cortex_xsoar.api_url is None:
            raise PaloAltoCortexXSOARValidationError(
                "palo_alto_cortex_xsoar.api_url cannot be None"
            )

        auth = Authentication(
            api_key=config.palo_alto_cortex_xsoar.api_key.get_secret_value(),
            api_key_id=config.palo_alto_cortex_xsoar.api_key_id,
            api_key_type=config.palo_alto_cortex_xsoar.api_key_type,
        )
        self.client_api = PaloAltoCortexXSOARClientAPI(
            auth=auth, api_url=str(config.palo_alto_cortex_xsoar.api_url)
        )
        self.converter: PaloAltoCortexXSOARConverter = PaloAltoCortexXSOARConverter()

        self.time_window = config.palo_alto_cortex_xsoar.time_window

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
            PaloAltoCortexXSOARExpectationError: If processing fails.

        """
        if not expectations:
            self.logger.info(f"{LOG_PREFIX} No expectations to process")
            return []

        try:
            self.logger.info(
                f"{LOG_PREFIX} Starting processing of {len(expectations)} expectations"
            )

            incidents = self._fetch_alerts_for_time_window(expectations)
            self.logger.info(
                f"{LOG_PREFIX} Fetched {len(incidents)} incidents from time window"
            )

            results = self._match_alerts_to_expectations(
                expectations, incidents, detection_helper
            )

            valid_count = sum(1 for r in results if r.is_valid)
            invalid_count = len(results) - valid_count

            self.logger.info(
                f"{LOG_PREFIX} Processing completed: {valid_count} valid, {invalid_count} invalid"
            )

            return results

        except Exception as e:
            raise PaloAltoCortexXSOARExpectationError(
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
    ) -> List[IncidentResult]:
        """Fetch all incidents from the configured time window or date signatures.

        Args:
            expectations: Optional list of expectations to extract date filters from.

        Returns:
            List of IncidentResult with extracted indicators.

        Raises:
            PaloAltoCortexXSOARAPIError: If API call fails.

        """
        try:
            end_time = self._extract_end_date_from_expectations(expectations)

            if end_time is None:
                end_time = datetime.now(timezone.utc)

            # Ensure end_time is aware
            if end_time.tzinfo is None:
                end_time = end_time.replace(tzinfo=timezone.utc)

            start_time = end_time - self.time_window

            self.logger.debug(
                f"{LOG_PREFIX} Delegating alert fetching to AlertFetcher for time window: {start_time} to {end_time}"
            )

            return self.alert_fetcher.fetch_alerts_for_time_window(
                start_time=start_time,
                end_time=end_time,
            )

        except Exception as e:
            raise PaloAltoCortexXSOARAPIError(
                f"Error fetching alerts for time window: {e}"
            ) from e

    def _match_alerts_to_expectations(
        self,
        batch: list[DetectionExpectation | PreventionExpectation],
        incidents: List[IncidentResult],
        detection_helper: Any,
    ) -> list[ExpectationResult]:
        """Match incidents to expectations and create results.

        Args:
            batch: Batch of expectations.
            incidents: List of IncidentResult containing extracted indicators.
            detection_helper: OpenAEV detection helper.

        Returns:
            List of ExpectationResult objects.

        """
        results = []

        for expectation in batch:
            try:
                matched = False
                traces = []

                for incident in incidents:
                    process_names = incident.indicators.oaev_implant
                    if self._expectation_matches_incident(
                        expectation, incident, process_names, detection_helper
                    ):
                        api_url = self.client_api.api_url
                        trace = TraceBuilder.create_incident_trace(incident, api_url)
                        traces.append(trace)

                        if isinstance(expectation, PreventionExpectation):
                            if any("Prevented" in action for action in incident.action):
                                matched = True
                                self.logger.debug(
                                    f"{LOG_PREFIX} Prevention expectation {expectation.inject_expectation_id}: "
                                    f"incident {incident.id} matched signature and action is prevented -> expectation satisfied"
                                )
                                break
                            self.logger.debug(
                                f"{LOG_PREFIX} Prevention expectation {expectation.inject_expectation_id}: "
                                f"incident {incident.id} matched signature but not prevented -> continuing search"
                            )
                        else:
                            if any(
                                "Detected" in action or "Prevented" in action
                                for action in incident.action
                            ):
                                matched = True
                                self.logger.debug(
                                    f"{LOG_PREFIX} Detection expectation {expectation.inject_expectation_id}: "
                                    f"incident {incident.id} matched signature ({incident.action}) -> expectation satisfied"
                                )
                                break

                if matched:
                    result_dict = {
                        "is_valid": True,
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
                    PaloAltoCortexXSOARExpectationError(f"Matching error: {e}"),
                    expectation,
                )
                results.append(error_result)

        return results

    def _expectation_matches_incident(
        self,
        expectation: DetectionExpectation | PreventionExpectation,
        incident: IncidentResult,
        process_names: list[str],
        detection_helper: Any,
    ) -> bool:
        """Check if an expectation matches the given incident using process names.

        Args:
            expectation: The expectation to match.
            incident: The IncidentResult data.
            process_names: Implant process names from indicators.oaev_implant.
            detection_helper: OpenAEV detection helper for matching.

        Returns:
            True if the expectation matches, False otherwise.

        """
        try:
            oaev_data = self.converter.convert_incident_to_oaev(incident)

            if not oaev_data:
                self.logger.debug(
                    f"{LOG_PREFIX} No OAEV data generated for incident {incident.id}"
                )
                return False

            oaev_data["parent_process_name"] = {
                "type": "simple",
                "data": process_names,
                "score": 95,
            }

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
                        f"{LOG_PREFIX} {sig_type} signature failed for incident {incident.id}"
                    )
                    return False

            self.logger.debug(
                f"{LOG_PREFIX} All signatures matched for expectation {expectation.inject_expectation_id} vs incident {incident.id}"
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
            "service_name": "PaloAltoCortexXSOARExpectationService",
            "supported_signatures": self.get_supported_signatures(),
            "flow_type": "all_at_once",
        }
