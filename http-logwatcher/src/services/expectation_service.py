import logging
from datetime import datetime, timezone
from typing import Any

from pyoaev.apis.inject_expectation.model.expectation import (
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.signatures.types import SignatureTypes
from src.models.expectation import ExpectationResult
from src.models.logline import ErrorLogLine, LogLine
from src.models.settings.config_loader import ConfigLoader
from src.services.converter import HTTPLogwatcherConverter
from src.services.exception import (
    HTTPLogwatcherExpectationError,
    HTTPLogwatcherFileError,
    HTTPLogwatcherValidationError,
)
from src.services.fetcher_logline import (
    AccessLogLineFetcher,
    ErrorLogLineFetcher,
    FetchResult,
)
from src.services.utils import SignatureExtractor, TraceBuilder

LOG_PREFIX = "[ExpectationService]"


class ExpectationService:
    """Service for processing HTTPLogwatcher expectations."""

    def __init__(
        self,
        config: ConfigLoader,
    ) -> None:
        """Initialize the HTTPLogwatcher expectation service.

        Args:
            config: Configuration loader for alternative initialization.

        Raises:
            HTTPLogwatcherValidationError: If required parameters are None.

        """
        self.logger: logging.Logger = logging.getLogger(__name__)

        if config is None:
            raise HTTPLogwatcherValidationError("config cannot be None")

        if config.http_logwatcher.logs_folder_path is None:
            raise HTTPLogwatcherValidationError(
                "http_logwatcher.logs_folder_path cannot be None"
            )

        self.converter: HTTPLogwatcherConverter = HTTPLogwatcherConverter()

        self.time_window = config.http_logwatcher.time_window

        self.access_logline_fetcher: AccessLogLineFetcher = AccessLogLineFetcher(
            config.http_logwatcher.logs_folder_path
        )

        self.error_logline_fetcher: ErrorLogLineFetcher = ErrorLogLineFetcher(
            config.http_logwatcher.logs_folder_path
        )

        self.logger.info(f"{LOG_PREFIX} Service initialized")

    def get_supported_signatures(self) -> list[SignatureTypes]:
        return [
            SignatureTypes.SIG_TYPE_SOURCE_IPV4_ADDRESS,
            SignatureTypes.SIG_TYPE_TARGET_IPV4_ADDRESS,
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
            HTTPLogwatcherExpectationError: If processing fails.

        """
        if not expectations:
            self.logger.info(f"{LOG_PREFIX} No expectations to process")
            return []

        try:
            self.logger.info(
                f"{LOG_PREFIX} Starting processing of {len(expectations)} expectations"
            )

            fetch_result = self._fetch_loglines_for_time_window(expectations)
            self.logger.info(
                f"{LOG_PREFIX} Fetched {len(fetch_result.loglines)} loglines from time window"
            )

            results = self._match_loglines_to_expectations(
                expectations, fetch_result, detection_helper
            )

            valid_count = sum(1 for r in results if r.is_valid)
            invalid_count = len(results) - valid_count

            self.logger.info(
                f"{LOG_PREFIX} Processing completed: {valid_count} valid, {invalid_count} invalid"
            )

            return results

        except Exception as e:
            raise HTTPLogwatcherExpectationError(
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

    def _fetch_loglines_for_time_window(
        self,
        expectations: list[DetectionExpectation | PreventionExpectation] | None = None,
    ) -> FetchResult:
        """Fetch all loglines from the configured time window or date signatures.

        Args:
            expectations: Optional list of expectations to extract date filters from.

        Returns:
            FetchResult with loglines and file_artifacts_by_case_id.

        Raises:
            HTTPLogwatcherFileError: If log file reading fails.

        """
        try:
            end_time = self._extract_end_date_from_expectations(expectations)

            if end_time is None:
                end_time = datetime.now(timezone.utc)

            start_time = end_time - self.time_window

            self.logger.debug(
                f"{LOG_PREFIX} Delegating logline fetching to LogLineFetcher for time window: {start_time} to {end_time}"
            )

            access_results = self.access_logline_fetcher.fetch_loglines_for_time_window(
                start_time=start_time,
                end_time=end_time,
            )
            access_loglines = access_results.loglines

            error_results = self.error_logline_fetcher.fetch_loglines_for_time_window(
                start_time=start_time,
                end_time=end_time,
            )
            error_loglines = error_results.loglines

            merged_loglines = FetchResult(
                loglines=access_loglines + error_loglines,
            )

            return merged_loglines

        except Exception as e:
            raise HTTPLogwatcherFileError(
                f"Error fetching loglines for time window: {e}"
            ) from e

    def _match_loglines_to_expectations(
        self,
        batch: list[DetectionExpectation | PreventionExpectation],
        fetch_result: FetchResult,
        detection_helper: Any,
    ) -> list[ExpectationResult]:
        """Match loglines to expectations and create results.

        Args:
            batch: Batch of expectations.
            fetch_result: FetchResult containing loglines.
            detection_helper: OpenAEV detection helper.

        Returns:
            List of ExpectationResult objects.

        """
        results = []

        for expectation in batch:
            try:
                matched = False
                traces = []

                for logline in fetch_result.loglines:
                    flag = False
                    try:
                        flag = self._expectation_matches_logline(
                            expectation, logline, detection_helper
                        )
                    except Exception as e:
                        self.logger.warning(
                            f"{LOG_PREFIX} Error in expectation matching: {e}"
                        )

                    if flag:
                        trace = TraceBuilder.create_logline_trace(logline)
                        traces.append(trace)

                        if isinstance(expectation, PreventionExpectation):
                            if isinstance(logline, ErrorLogLine):
                                matched = True
                                self.logger.debug(
                                    f"{LOG_PREFIX} Prevention expectation {expectation.inject_expectation_id}: "
                                    f"logline matched signature and action is prevented -> expectation satisfied"
                                )
                                break
                            self.logger.debug(
                                f"{LOG_PREFIX} Prevention expectation {expectation.inject_expectation_id}: "
                                f"logline matched signature but not prevented -> continuing search"
                            )
                        else:
                            matched = True
                            self.logger.debug(
                                f"{LOG_PREFIX} Detection expectation {expectation.inject_expectation_id}: "
                                f"logline matched signature -> expectation satisfied"
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
                    HTTPLogwatcherExpectationError(f"Matching error: {e}"),
                    expectation,
                )
                results.append(error_result)

        return results

    def _expectation_matches_logline(
        self,
        expectation: DetectionExpectation | PreventionExpectation,
        logline: LogLine,
        detection_helper: Any,
    ) -> bool:
        """Check if an expectation matches the given logline using process names.

        Args:
            expectation: The expectation to match.
            logline: The logline data.
            detection_helper: OpenAEV detection helper for matching.

        Returns:
            True if the expectation matches, False otherwise.

        """
        oaev_data = self.converter.convert_logline_to_oaev(logline)

        if not oaev_data:
            self.logger.debug(
                f"{LOG_PREFIX} No OAEV data generated for logline {logline}"
            )
            return False

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
            key: value for key, value in oaev_data.items() if key in supported_sig_names
        }
        self.logger.debug(f"{LOG_PREFIX} Available OAEV data: {list(oaev_data.keys())}")
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

            # looking for an ANY result rather than ALL (hackish solution)
            match_flags = []
            for signature in signatures:
                match_single_flag = detection_helper.match_alert_elements(
                    [
                        signature,
                    ],
                    filtered_data,
                )
                match_flags.append(match_single_flag)
            match_result = any(match_flags)

            self.logger.debug(
                f"{LOG_PREFIX} Detection helper result for {sig_type}: {match_result}"
            )

            if not match_result:
                self.logger.debug(
                    f"{LOG_PREFIX} {sig_type} signature failed for logline {logline}"
                )
                return False

        self.logger.debug(
            f"{LOG_PREFIX} All signatures matched for expectation {expectation.inject_expectation_id} vs logline {logline}"
        )
        return True

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
            "service_name": "HTTPLogwatcherExpectationService",
            "supported_signatures": self.get_supported_signatures(),
            "flow_type": "all_at_once",
        }
