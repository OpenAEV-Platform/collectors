"""Splunk ES Expectation Service Provider.

This module contains all the Splunk ES-specific logic for handling expectations.
It implements the service provider protocol and defines which signatures to support,
how to fetch data, and how to process expectations.
"""

import logging
from datetime import timedelta
from typing import Any

from pyoaev.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.helpers import OpenAEVDetectionHelper  # type: ignore[import-untyped]
from pyoaev.signatures.types import SignatureTypes  # type: ignore[import-untyped]

from ..collector.models import ExpectationResult
from ..models.configs.config_loader import ConfigLoader
from .client_api import SplunkESClientAPI
from .converter import Converter
from .exception import (
    SplunkESAPIError,
    SplunkESConfigurationError,
    SplunkESDataConversionError,
    SplunkESExpectationError,
    SplunkESMatchingError,
    SplunkESNetworkError,
    SplunkESNoAlertsFoundError,
    SplunkESNoMatchingAlertsError,
    SplunkESServiceError,
    SplunkESValidationError,
)
from .models import SplunkESAlert
from .utils.regex_engine import RegexSignatureEngine, Signature

LOG_PREFIX = "[SplunkESExpectationService]"


class SplunkESExpectationService:
    """Splunk ES-specific service provider for expectation handling.

    This class contains all the business logic specific to Splunk ES:
    - Which signature types to support (all types, dynamically from SignatureTypes)
    - How to fetch data from Splunk ES
    - How to validate expectations against data
    - How to handle batching and optimization
    """

    # Dynamic support: every SignatureTypes member is supported, so this
    # list tracks the upstream enum across pyoaev versions without hardcoding.
    SUPPORTED_SIGNATURES = list(SignatureTypes)

    # Signature types the SPL query already filters on (the enough-filter):
    # source/target IPs, both hostname flavors, and the date bounds. They
    # never participate in raw-text matching.
    _FILTER_SIGNATURE_TYPES = frozenset(
        {
            "source_ipv4_address",
            "source_ipv6_address",
            "target_ipv4_address",
            "target_ipv6_address",
            "hostname",
            "target_hostname_address",
            "start_date",
            "end_date",
        }
    )

    def __init__(self, config: ConfigLoader | None = None) -> None:
        """Initialize the Splunk ES service provider.

        Args:
            config: Configuration loader instance for service settings.

        Raises:
            SplunkESValidationError: If config is None.
            SplunkESConfigurationError: If service components initialization fails.

        """
        if config is None:
            raise SplunkESValidationError("Config is required for expectation service")

        self.logger = logging.getLogger(__name__)
        self.config = config

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Initializing Splunk ES service components..."
            )
            self.client_api = SplunkESClientAPI(config)
            self.converter = Converter()
            self._regex_engine = RegexSignatureEngine()
            self.logger.debug(
                f"{LOG_PREFIX} Raw-text regex signature engine initialized for alert matching"
            )
            self.logger.info(
                f"{LOG_PREFIX} Splunk ES expectation service initialized successfully"
            )
        except (SplunkESValidationError, SplunkESConfigurationError):
            raise
        except Exception as e:
            raise SplunkESConfigurationError(
                f"Failed to initialize Splunk ES service components: {e}"
            ) from e

        if (
            hasattr(config, "splunk_es")
            and hasattr(config.splunk_es, "time_window")
            and config.splunk_es.time_window
        ):
            self.time_window = config.splunk_es.time_window
            self.logger.debug(
                f"{LOG_PREFIX} Using configured time window: {self.time_window}"
            )
        else:
            self.time_window = timedelta(hours=1)
            self.logger.warning(
                f"{LOG_PREFIX} No time_window configured, using default 1 hour"
            )

        if hasattr(config, "splunk_es"):
            self.max_retry = getattr(config.splunk_es, "max_retry", 3)
            self.offset = getattr(
                config.splunk_es, "offset", timedelta(seconds=30)
            ).total_seconds()
            self.logger.debug(
                f"{LOG_PREFIX} Using configured retry parameters: max_retry={self.max_retry}, offset={self.offset}s"
            )
        else:
            self.max_retry = 3
            self.offset = 30
            self.logger.warning(
                f"{LOG_PREFIX} No retry configuration found, using defaults: max_retry={self.max_retry}, offset={self.offset}s"
            )

    def get_supported_signatures(self) -> list[SignatureTypes]:
        """Get the signature types this service supports.

        Returns:
            List of SignatureTypes that this service can process.

        """
        self.logger.debug(
            f"{LOG_PREFIX} Returning {len(self.SUPPORTED_SIGNATURES)} supported signature types"
        )
        return list(self.SUPPORTED_SIGNATURES)

    def handle_batch_expectations(
        self,
        expectations: list[DetectionExpectation | PreventionExpectation],
        detection_helper: OpenAEVDetectionHelper,
    ) -> list[ExpectationResult]:
        """Handle a batch of expectations.

        Processes each expectation individually and collects results,
        handling errors gracefully for individual expectations.

        Args:
            expectations: List of expectations to process.
            detection_helper: OpenAEV detection helper.

        Returns:
            List of ExpectationResult objects.

        Raises:
            SplunkESExpectationError: If batch processing fails.

        """
        if not expectations:
            self.logger.info(f"{LOG_PREFIX} No expectations to process")
            return []

        try:
            self.logger.info(
                f"{LOG_PREFIX} Starting batch processing of {len(expectations)} expectations"
            )

            all_results_with_expectations_associated = []

            for i, expectation in enumerate(expectations, 1):
                expectation_id = str(expectation.inject_expectation_id)
                self.logger.debug(
                    f"{LOG_PREFIX} Processing expectation {i}/{len(expectations)}: {expectation_id}"
                )

                try:
                    result = self.process_expectation(expectation, detection_helper)
                    if result.is_valid:
                        self.logger.debug(
                            f"{LOG_PREFIX} Expectation {expectation_id} processed successfully"
                        )
                    else:
                        self.logger.debug(
                            f"{LOG_PREFIX} Expectation {expectation_id} failed validation"
                        )

                except SplunkESServiceError as e:
                    self.logger.warning(
                        f"{LOG_PREFIX} Splunk ES service error for expectation {expectation_id}: {e}"
                    )
                    result = self._create_error_result_object(e, expectation)
                except Exception as e:
                    self.logger.error(
                        f"{LOG_PREFIX} Unexpected error processing expectation {expectation_id}: {e}"
                    )
                    result = self._create_error_result_object(
                        SplunkESExpectationError(f"Unexpected error: {e}"),
                        expectation,
                    )

                all_results_with_expectations_associated.append(result)

            valid_count = sum(
                1 for r in all_results_with_expectations_associated if r.is_valid
            )
            invalid_count = len(all_results_with_expectations_associated) - valid_count

            self.logger.info(
                f"{LOG_PREFIX} Batch expectation processing: processed {len(expectations)} items -> {len(all_results_with_expectations_associated)} results"
            )
            self.logger.info(
                f"{LOG_PREFIX} Batch processing completed: {valid_count} valid, {invalid_count} invalid"
            )

            return all_results_with_expectations_associated

        except Exception as e:
            raise SplunkESExpectationError(
                f"Error in handle_batch_expectations: {e}"
            ) from e

    def process_expectation(
        self,
        expectation: DetectionExpectation | PreventionExpectation,
        detection_helper: OpenAEVDetectionHelper,
    ) -> ExpectationResult:
        """Process a single expectation based on its type.

        Args:
            expectation: The expectation to process (Detection only for Splunk ES).
            detection_helper: OpenAEV detection helper instance.

        Returns:
            ExpectationResult containing the processing outcome.

        Raises:
            SplunkESExpectationError: If expectation type is unsupported.

        """
        expectation_id = str(expectation.inject_expectation_id)

        if isinstance(expectation, DetectionExpectation):
            self.logger.debug(
                f"{LOG_PREFIX} Processing detection expectation: {expectation_id}"
            )
            return self.handle_detection_expectation(expectation, detection_helper)
        elif isinstance(expectation, PreventionExpectation):
            self.logger.warning(
                f"{LOG_PREFIX} Splunk ES service warning for expectation {expectation_id}: Splunk ES only supports DetectionExpectations, not PreventionExpectations, marking them as invalid"
            )
            return ExpectationResult(
                expectation_id=expectation_id,
                is_valid=False,
                expectation=expectation,
                error_message="Splunk ES only supports DetectionExpectations, not PreventionExpectations",
            )
        else:
            self.logger.error(
                f"{LOG_PREFIX} Unsupported expectation type for {expectation_id}: {type(expectation).__name__}"
            )
            raise SplunkESExpectationError(
                f"Unsupported expectation type: {type(expectation).__name__}"
            )

    def handle_detection_expectation(
        self,
        expectation: DetectionExpectation,
        detection_helper: OpenAEVDetectionHelper,
    ) -> ExpectationResult:
        """Handle a detection expectation.

        Args:
            expectation: The detection expectation to process.
            detection_helper: OpenAEV detection helper instance.

        Returns:
            ExpectationResult containing the processing outcome.

        """
        result_dict = self._handle_expectation(
            expectation, detection_helper, "detection"
        )
        return self._convert_dict_to_result(result_dict, expectation)

    def handle_prevention_expectation(
        self,
        expectation: PreventionExpectation,
        detection_helper: OpenAEVDetectionHelper,
    ) -> ExpectationResult:
        """Handle a prevention expectation.

        Since Splunk ES only supports detection, this method logs a warning
        and returns an invalid result instead of throwing an error.

        Args:
            expectation: The prevention expectation to process.
            detection_helper: OpenAEV detection helper instance.

        Returns:
            ExpectationResult indicating that prevention is not supported.

        """
        expectation_id = str(expectation.inject_expectation_id)
        self.logger.warning(
            f"{LOG_PREFIX} Splunk ES service error for expectation {expectation_id}: Splunk ES only supports DetectionExpectations, not PreventionExpectations"
        )
        return ExpectationResult(
            expectation_id=expectation_id,
            is_valid=False,
            expectation=expectation,
            error_message="Splunk ES only supports DetectionExpectations, not PreventionExpectations",
        )

    def _handle_expectation(
        self,
        expectation: DetectionExpectation,
        detection_helper: OpenAEVDetectionHelper,
        expectation_type: str,
    ) -> dict[str, Any]:
        """Core logic for handling expectations.

        Fetches raw Splunk ES alerts for the expectation's search signatures,
        then matches the fetched alerts against the remaining expectation
        signatures by searching each alert's raw event text
        (``_raw``) with the raw-text regex signature engine.

        Args:
            expectation: The expectation to process.
            detection_helper: OpenAEV detection helper instance (retained for
                protocol compatibility; matching is delegated to the
                raw-text regex engine and does not gate on this helper).
            expectation_type: Type of expectation ('detection').

        Returns:
            Dictionary containing processing results.

        Raises:
            SplunkESExpectationError: If expectation processing fails.

        """
        expectation_id = expectation.inject_expectation_id

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Starting {expectation_type} expectation processing: {expectation_id}"
            )

            self.logger.debug(f"{LOG_PREFIX} Extracting signatures from expectation...")
            search_signatures, matching_signatures = self._extract_signatures(
                expectation
            )
            self.logger.debug(
                f"{LOG_PREFIX} Extracted {len(search_signatures)} search signatures, {len(matching_signatures)} matching signatures"
            )

            self.logger.debug(
                f"{LOG_PREFIX} Fetching Splunk ES data for {expectation_type} expectation..."
            )
            splunk_es_data = self.client_api.fetch_with_retry(
                search_signatures, expectation_type, self.max_retry, int(self.offset)
            )
            self.logger.debug(
                f"{LOG_PREFIX} Fetched {len(splunk_es_data)} data items from Splunk ES"
            )

            self.logger.debug(
                f"{LOG_PREFIX} Matching fetched alerts against expectation signatures via raw-text regex engine..."
            )
            result = self._match(splunk_es_data, matching_signatures, expectation_type)

            return result

        except (
            SplunkESServiceError,
            SplunkESAPIError,
            SplunkESNetworkError,
            SplunkESDataConversionError,
        ):
            raise
        except Exception as e:
            raise SplunkESExpectationError(
                f"Unexpected error processing expectation: {e}"
            ) from e

    def _extract_signatures(
        self, expectation: DetectionExpectation
    ) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        """Extract and filter signatures from expectation.

        Args:
            expectation: The expectation to extract signatures from.

        Returns:
            Tuple of (search_signatures, matching_signatures):
            - search_signatures: signatures for API query building
            - matching_signatures: signatures for alert matching (excludes date metadata)

        Raises:
            SplunkESExpectationError: If signature extraction fails.

        """
        try:
            all_signatures = [
                {"type": sig.type.value, "value": sig.value}
                for sig in expectation.inject_expectation_signatures
            ]
            self.logger.debug(
                f"{LOG_PREFIX} Found {len(all_signatures)} total signatures in expectation"
            )

            # All signature types are supported now: the search keeps the
            # full list unfiltered (preserves fetch_with_retry's non-empty
            # contract). Filter types (IPs, hostnames, dates) are the
            # enough-filter the query already applies; content types are
            # carried by the matcher only.
            search_signatures = all_signatures

            matching_signatures = [
                sig
                for sig in search_signatures
                if sig["type"] not in self._FILTER_SIGNATURE_TYPES
            ]

            self.logger.debug(
                f"{LOG_PREFIX} Using all {len(search_signatures)} signatures for search "
                f"(no type filtering) and {len(matching_signatures)} content signatures "
                f"(filter types excluded from matching)"
            )

            return search_signatures, matching_signatures

        except Exception as e:
            raise SplunkESExpectationError(
                f"Failed to extract signatures from expectation: {e}"
            ) from e

    def _match(
        self,
        splunk_es_data: list[SplunkESAlert],
        matching_signatures: list[dict[str, str]],
        expectation_type: str,
    ) -> dict[str, Any]:
        """Match fetched Splunk ES alerts against expectation signatures.

        Matching is delegated to the raw-text regex signature engine: each
        alert's raw event text is searched for the literal values of the
        matching signatures. The raw text is the alert's ``_raw`` field when
        it holds a non-empty string, otherwise a flattened ``key=value``
        representation of the whole raw row, so matching does not depend on
        any particular structured field names. When the content set is
        empty, the query's enough-filter is the only filter and the first
        fetched alert is accepted.

        Args:
            splunk_es_data: List of fetched Splunk ES alerts.
            matching_signatures: Content signatures to match against (filter
                types excluded upstream; empty means accept what the query
                fetched).
            expectation_type: Type of expectation ('detection').

        Returns:
            Result dictionary with match status and matching data (the
            matched alert's converted data, or its raw row when conversion
            yields nothing).

        Raises:
            SplunkESNoAlertsFoundError: If no data available for matching.
            SplunkESNoMatchingAlertsError: If no matching alerts found.
            SplunkESMatchingError: If matching process fails.

        """
        try:
            if not splunk_es_data:
                self.logger.debug(f"{LOG_PREFIX} No alerts available for matching")
                raise SplunkESNoAlertsFoundError("No data available for matching")

            if not matching_signatures:
                # No content signatures: the query's enough-filter is the only
                # filter, so accept what it fetched.
                self.logger.debug(
                    f"{LOG_PREFIX} No content signatures: accepting fetched alerts "
                    f"(query already filtered)"
                )
                alert = splunk_es_data[0]
                converted = self.converter.convert_data_to_oaev_data(alert)
                matched_item = converted[0] if converted else (alert._raw or {})
                self.logger.info(
                    f"{LOG_PREFIX} Successful match found for {expectation_type} expectation"
                )
                return {
                    "is_valid": True,
                    "matching_data": [matched_item],
                    "total_data_found": len(splunk_es_data),
                }

            self.logger.debug(
                f"{LOG_PREFIX} Matching is delegated to the raw-text regex engine: "
                f"{len(splunk_es_data)} alerts against {len(matching_signatures)} signatures"
            )

            engine_signatures = [
                Signature(type=sig["type"], value=sig["value"])
                for sig in matching_signatures
            ]

            for i, alert in enumerate(splunk_es_data):
                self.logger.debug(
                    f"{LOG_PREFIX} Matching alert {i + 1}/{len(splunk_es_data)}"
                )

                raw_text = self._regex_engine.raw_text_from(alert._raw)

                if raw_text and self._regex_engine.matches(raw_text, engine_signatures):
                    self.logger.debug(f"{LOG_PREFIX} Match found for alert {i + 1}!")

                    self.logger.info(
                        f"{LOG_PREFIX} Successful match found for {expectation_type} expectation"
                    )

                    converted = self.converter.convert_data_to_oaev_data(alert)
                    matched_item = converted[0] if converted else (alert._raw or {})
                    self.logger.debug(f"{LOG_PREFIX} Matching data: {matched_item}")

                    result = {
                        "is_valid": True,
                        "matching_data": [matched_item],
                        "total_data_found": len(splunk_es_data),
                    }

                    return result

                self.logger.debug(f"{LOG_PREFIX} No match for alert {i + 1}")

            self.logger.info(
                f"{LOG_PREFIX} No matching alerts found after checking {len(splunk_es_data)} alerts"
            )
            raise SplunkESNoMatchingAlertsError()

        except (
            SplunkESServiceError,
            SplunkESNoAlertsFoundError,
            SplunkESNoMatchingAlertsError,
        ):
            raise
        except Exception as e:
            raise SplunkESMatchingError() from e

    def _create_error_result(
        self,
        error: SplunkESServiceError,
        expectation: DetectionExpectation | None = None,
    ) -> dict[str, Any]:
        """Create an error result dictionary from a Splunk ES service error.

        Args:
            error: The Splunk ES service error that occurred.
            expectation: Optional expectation object that caused the error.

        Returns:
            Dictionary containing error details and metadata.

        """
        result = {
            "is_valid": False,
            "error": str(error),
            "error_type": error.__class__.__name__,
        }

        if hasattr(error, "status_code") and error.status_code:
            result["status_code"] = error.status_code

        if hasattr(error, "response_data") and error.response_data:
            result["response_data"] = error.response_data

        if expectation:
            result["expectation"] = expectation
            result["expectation_id"] = str(expectation.inject_expectation_id)

        return result

    def _create_error_result_object(
        self,
        error: SplunkESServiceError,
        expectation: DetectionExpectation | None = None,
    ) -> ExpectationResult:
        """Create an ExpectationResult object from a Splunk ES service error.

        Args:
            error: The Splunk ES service error that occurred.
            expectation: Optional expectation object that caused the error.

        Returns:
            ExpectationResult object with error details.

        """
        expectation_id = (
            str(expectation.inject_expectation_id) if expectation else "unknown"
        )

        error_message = str(error)
        if hasattr(error, "status_code") and error.status_code:
            error_message += f" (Status: {error.status_code})"

        return ExpectationResult(
            expectation_id=expectation_id,
            is_valid=False,
            expectation=expectation,
            error_message=error_message,
        )

    def _convert_dict_to_result(
        self,
        result_dict: dict[str, Any],
        expectation: DetectionExpectation,
    ) -> ExpectationResult:
        """Convert a dictionary result to ExpectationResult object.

        Args:
            result_dict: Dictionary containing processing results.
            expectation: The expectation that was processed.

        Returns:
            ExpectationResult object with structured data.

        """
        return ExpectationResult(
            expectation_id=str(expectation.inject_expectation_id),
            is_valid=result_dict.get("is_valid", False),
            expectation=expectation,
            matched_alerts=result_dict.get("matching_data"),
            error_message=result_dict.get("error"),
        )

    def get_service_info(self) -> dict[str, Any]:
        """Get information about this service provider.

        Returns:
            Dictionary containing service metadata and capabilities.

        """
        info = {
            "service_name": "Splunk ES",
            "supported_signatures": [sig.value for sig in self.SUPPORTED_SIGNATURES],
            "supports_detection": True,
            "supports_prevention": False,
            "description": f"Splunk ES expectation validation service ({len(self.SUPPORTED_SIGNATURES)} signature types, detection only)",
        }
        self.logger.debug(f"{LOG_PREFIX} Service info: {info}")
        return info
