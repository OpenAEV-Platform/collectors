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
            SignatureTypes.SIG_TYPE_START_DATE,
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

    def _extract_date_signatures(
        self,
        expectations: list[DetectionExpectation | PreventionExpectation] | None = None,
    ) -> tuple[datetime | None, datetime | None]:
        """Extract start_date and end_date from expectation signatures.

        Args:
            expectations: List of expectations to extract dates from.

        Returns:
            Tuple of (start_date, end_date) as datetime or None.

        """
        start_date = self._extract_start_date_from_expectations(expectations)
        end_date = self._extract_end_date_from_expectations(expectations)

        if start_date or end_date:
            self.logger.debug(
                f"{LOG_PREFIX} Extracted date signatures: start_date={start_date}, end_date={end_date}"
            )
        return start_date, end_date

    def _extract_start_date_from_expectations(
        self,
        expectations: list[DetectionExpectation | PreventionExpectation] | None = None,
    ) -> datetime | None:
        """Extract and normalize start_date from expectation signatures."""
        start_date = SignatureExtractor.extract_start_date(expectations)
        if start_date and start_date.tzinfo is None:
            # Keep previous behavior expected by tests: naive date => UTC.
            start_date = start_date.replace(tzinfo=timezone.utc)
        return start_date

    def _extract_end_date_from_expectations(
        self,
        expectations: list[DetectionExpectation | PreventionExpectation] | None = None,
    ) -> datetime | None:
        """Extract and normalize end_date from expectation signatures."""
        end_date = SignatureExtractor.extract_end_date(expectations)
        if end_date and end_date.tzinfo is None:
            # Keep previous behavior expected by tests: naive date => UTC.
            end_date = end_date.replace(tzinfo=timezone.utc)
        return end_date

    def _fetch_alerts_for_time_window(
        self,
        expectations: list[DetectionExpectation | PreventionExpectation] | None = None,
    ) -> List[IncidentResult]:
        """Fetch all incidents for the expectation time window.

        Uses start_date/end_date from expectation signatures directly when available.
        Falls back to now() - time_window / now() only when no date signatures exist.

        Args:
            expectations: Optional list of expectations to extract date filters from.

        Returns:
            List of IncidentResult with extracted indicators.

        Raises:
            PaloAltoCortexXSOARAPIError: If API call fails.

        """
        try:
            start_date, end_date = self._extract_date_signatures(expectations)

            if start_date and end_date:
                # Use expectation signature dates directly
                start_time = start_date
                end_time = end_date
                self.logger.debug(
                    f"{LOG_PREFIX} Using expectation date signatures for incident retrieval: "
                    f"{start_time} to {end_time}"
                )
            elif end_date:
                # Only end_date available, compute start from time_window
                end_time = end_date
                start_time = end_time - self.time_window
                self.logger.debug(
                    f"{LOG_PREFIX} Using end_date signature with time_window fallback for start: "
                    f"{start_time} to {end_time}"
                )
            elif start_date:
                # Only start_date available, use now() as end
                start_time = start_date
                end_time = datetime.now(timezone.utc)
                self.logger.debug(
                    f"{LOG_PREFIX} Using start_date signature with now() as end: "
                    f"{start_time} to {end_time}"
                )
            else:
                # No date signatures at all — fallback to time_window from now()
                end_time = datetime.now(timezone.utc)
                start_time = end_time - self.time_window
                self.logger.debug(
                    f"{LOG_PREFIX} No date signatures found, using time_window fallback: "
                    f"{start_time} to {end_time}"
                )

            self.logger.debug(
                f"{LOG_PREFIX} Delegating alert fetching to AlertFetcher for time window: "
                f"{start_time} to {end_time}"
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
        """Match incidents/alerts to expectations and create results.

        Incidents already contain only alerts whose detection_timestamp falls
        within the expectation time window (filtered by AlertFetcher).

        For each expectation:
        1. If at least one alert exists in an incident -> is_detected = True.
        2. Derive is_prevented only from matched alerts' action status.
        3. IP/ProcessName signatures are used when present but are not mandatory
           for detection matching.

        Args:
            batch: Batch of expectations.
            incidents: List of IncidentResult with pre-filtered alerts.
            detection_helper: OpenAEV detection helper.

        Returns:
            List of ExpectationResult objects.

        """
        results = []

        for expectation in batch:
            try:
                matched = False
                is_prevented = False
                traces = []

                for incident in incidents:
                    # Alerts are already filtered by timestamp in AlertFetcher.
                    # Some legacy fixtures still provide incident.action only.
                    matched_alerts = incident.alerts
                    has_alert_signal = bool(matched_alerts) or bool(incident.action)
                    if not has_alert_signal:
                        continue

                    # Check if IP/ProcessName signatures match (optional, not mandatory)
                    process_names = incident.indicators.oaev_implant
                    has_signature_match = self._expectation_matches_incident(
                        expectation, incident, process_names, detection_helper
                    )

                    # Detection: at least one alert in the time window is sufficient
                    # Signature match strengthens confidence but is not mandatory
                    if has_signature_match or not self._has_matchable_signatures(
                        expectation
                    ):
                        # Derive is_prevented from available matched status signals.
                        incident_prevented = False
                        for alert in matched_alerts:
                            action_value = alert.action_pretty or alert.action or ""
                            if "Prevented" in action_value:
                                incident_prevented = True
                                break
                        if not matched_alerts:
                            incident_prevented = any(
                                "Prevented" in action for action in incident.action
                            )

                        # Preserve previous collector behavior: a prevention expectation
                        # only matches if the matched signal is actually prevented.
                        if (
                            isinstance(expectation, PreventionExpectation)
                            and not incident_prevented
                        ):
                            self.logger.debug(
                                f"{LOG_PREFIX} Expectation {expectation.inject_expectation_id}: "
                                f"incident {incident.id} detected but not prevented, continuing search"
                            )
                            continue

                        matched = True
                        is_prevented = incident_prevented
                        api_url = self.client_api.api_url
                        trace = TraceBuilder.create_incident_trace(incident, api_url)
                        traces.append(trace)

                        self.logger.debug(
                            f"{LOG_PREFIX} Expectation {expectation.inject_expectation_id}: "
                            f"incident {incident.id} has {len(matched_alerts)} alert(s) in time window, "
                            f"signature_match={has_signature_match}, is_prevented={is_prevented}"
                        )
                        break

                if matched:
                    # For PreventionExpectation, is_valid requires is_prevented
                    if isinstance(expectation, PreventionExpectation):
                        is_valid = is_prevented
                    else:
                        # DetectionExpectation: at least one alert in window = detected
                        is_valid = True

                    result_dict = {
                        "is_valid": is_valid,
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

    def _has_matchable_signatures(
        self,
        expectation: DetectionExpectation | PreventionExpectation,
    ) -> bool:
        """Check if the expectation has non-date signatures that can be matched.

        Args:
            expectation: The expectation to check.

        Returns:
            True if there are IP or ProcessName signatures to match against.

        """
        supported_signatures = self.get_supported_signatures()
        signature_groups = SignatureExtractor.group_signatures_by_type(
            expectation, supported_signatures
        )
        return len(signature_groups) > 0

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

            # If no matchable signatures exist, we can't match by signature
            if not signature_groups:
                self.logger.debug(
                    f"{LOG_PREFIX} No matchable signatures for expectation "
                    f"{expectation.inject_expectation_id}, skipping signature matching"
                )
                return False

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
                f"{LOG_PREFIX} All signatures matched for expectation "
                f"{expectation.inject_expectation_id} vs incident {incident.id}"
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
