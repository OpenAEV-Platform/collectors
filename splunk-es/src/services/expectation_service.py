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

LOG_PREFIX = "[SplunkESExpectationService]"


class SplunkESExpectationService:
    """Splunk ES-specific service provider for expectation handling.

    This class contains all the business logic specific to Splunk ES:
    - Which signature types to support (only IPV4/6 addresses)
    - How to fetch data from Splunk ES
    - How to validate expectations against data
    - How to handle batching and optimization
    """

    SUPPORTED_SIGNATURES = [
        SignatureTypes.SIG_TYPE_SOURCE_IPV4_ADDRESS,
        SignatureTypes.SIG_TYPE_TARGET_IPV4_ADDRESS,
        SignatureTypes.SIG_TYPE_SOURCE_IPV6_ADDRESS,
        SignatureTypes.SIG_TYPE_TARGET_IPV6_ADDRESS,
        SignatureTypes.SIG_TYPE_START_DATE,
        SignatureTypes.SIG_TYPE_END_DATE,
        SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
    ]

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
        return self.SUPPORTED_SIGNATURES

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

        Args:
            expectation: The expectation to process.
            detection_helper: OpenAEV detection helper instance.
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
                f"{LOG_PREFIX} Converting Splunk ES data to OAEV format..."
            )
            oaev_data = self.converter.convert_data_to_oaev_data(splunk_es_data)
            self.logger.debug(
                f"{LOG_PREFIX} Converted to {len(oaev_data)} OAEV data items"
            )

            self.logger.debug(
                f"{LOG_PREFIX} Matching data against expectation signatures..."
            )
            result = self._match(
                oaev_data, matching_signatures, detection_helper, expectation_type
            )

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

            search_signatures = [
                sig
                for sig in all_signatures
                if sig["type"] in [s.value for s in self.SUPPORTED_SIGNATURES]
            ]

            date_signature_types = [
                SignatureTypes.SIG_TYPE_START_DATE.value,
                SignatureTypes.SIG_TYPE_END_DATE.value,
            ]
            matching_signatures = [
                sig
                for sig in search_signatures
                if sig["type"] not in date_signature_types
            ]

            self.logger.debug(
                f"{LOG_PREFIX} Filtered to {len(search_signatures)} search signatures and {len(matching_signatures)} matching signatures"
            )

            return search_signatures, matching_signatures

        except Exception as e:
            raise SplunkESExpectationError(
                f"Failed to extract signatures from expectation: {e}"
            ) from e

    def _match(
        self,
        oaev_data: list[dict[str, Any]],
        matching_signatures: list[dict[str, str]],
        detection_helper: OpenAEVDetectionHelper,
        expectation_type: str,
    ) -> dict[str, Any]:
        """Match OAEV data against expectation signatures.

        Args:
            oaev_data: List of OAEV formatted data.
            matching_signatures: Signatures to match against.
            detection_helper: OpenAEV detection helper.
            expectation_type: Type of expectation ('detection').

        Returns:
            Result dictionary with match status and matching data.

        Raises:
            SplunkESNoAlertsFoundError: If no data available for matching.
            SplunkESNoMatchingAlertsError: If no matching alerts found.
            SplunkESMatchingError: If matching process fails.

        """
        try:
            if not oaev_data:
                self.logger.debug(f"{LOG_PREFIX} No OAEV data available for matching")
                raise SplunkESNoAlertsFoundError("No data available for matching")

            self.logger.debug(
                f"{LOG_PREFIX} Attempting to match {len(oaev_data)} data items against {len(matching_signatures)} signatures"
            )

            for i, data_item in enumerate(oaev_data):
                self.logger.debug(f"{i} data_item: {data_item}")
                self.logger.debug(
                    f"{LOG_PREFIX} Matching data item {i + 1}/{len(oaev_data)}"
                )

                available_signatures = [
                    sig for sig in matching_signatures if sig["type"] in data_item
                ]

                self.logger.debug(
                    f"{LOG_PREFIX} Data item {i + 1} has {len(available_signatures)} available signatures out of {len(matching_signatures)} total signatures"
                )

                if available_signatures:
                    try:
                        self.logger.debug(
                            f"{LOG_PREFIX} Testing match for data item {i + 1} with {len(available_signatures)} signatures"
                        )

                        # Use detection_helper with filtered signatures per type
                        if self._match_with_detection_helper(
                            available_signatures, data_item, detection_helper
                        ):
                            self.logger.debug(
                                f"{LOG_PREFIX} Match found for data item {i + 1}!"
                            )

                            self.logger.info(
                                f"{LOG_PREFIX} Successful match found for {expectation_type} expectation"
                            )
                            self.logger.debug(
                                f"{LOG_PREFIX} Matching data: {data_item}"
                            )

                            result = {
                                "is_valid": True,
                                "matching_data": [data_item],
                                "total_data_found": len(oaev_data),
                            }

                            return result
                        else:
                            self.logger.debug(
                                f"{LOG_PREFIX} No match for data item {i + 1}"
                            )
                            continue
                    except Exception as e:
                        self.logger.error(
                            f"{LOG_PREFIX} Error during matching for data item {i + 1}: {e}"
                        )
                        raise SplunkESNoMatchingAlertsError() from e
                else:
                    self.logger.debug(
                        f"{LOG_PREFIX} Data item {i + 1} has no available signatures to match against"
                    )

            self.logger.info(
                f"{LOG_PREFIX} No matching alerts found after checking {len(oaev_data)} data items"
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

    def _match_with_detection_helper(
        self,
        signatures: list[dict[str, str]],
        data_item: dict[str, Any],
        detection_helper: OpenAEVDetectionHelper,
    ) -> bool:
        """Match signatures using detection_helper with proper OR logic.

        Args:
            signatures: List of signature dictionaries.
            data_item: OAEV data item to match against.
            detection_helper: OpenAEV detection helper instance.

        Returns:
            True if matching succeeds, False otherwise.

        Logic:
        1. Parent process: MUST match exactly (if present) - stop if False
        2. Source IPs: Call detection_helper for each IP individually, stop at first match (OR logic)
        3. Target IPs: Call detection_helper for each IP individually, stop at first match (OR logic)
        4. Must have parent_process=True AND (at least one src_ip=True OR at least one dst_ip=True)

        """
        try:
            signature_groups: dict[str, list[dict[str, str]]] = {}
            for sig in signatures:
                sig_type = sig["type"]
                if sig_type not in signature_groups:
                    signature_groups[sig_type] = []
                signature_groups[sig_type].append(sig)

            self.logger.debug(
                f"{LOG_PREFIX} Processing {len(signature_groups)} signature groups"
            )

            parent_process_match = False
            source_ip_match = False
            target_ip_match = False

            if "parent_process_name" in signature_groups:
                parent_sigs = signature_groups["parent_process_name"]
                self.logger.debug(
                    f"{LOG_PREFIX} Checking parent process with {len(parent_sigs)} signatures"
                )

                filtered_data = {
                    k: v for k, v in data_item.items() if k == "parent_process_name"
                }

                parent_process_match = detection_helper.match_alert_elements(
                    parent_sigs, filtered_data
                )

                self.logger.debug(
                    f"{LOG_PREFIX} Parent process match: {parent_process_match}"
                )

                if not parent_process_match:
                    self.logger.debug(f"{LOG_PREFIX} Parent process failed - stopping")
                    return False

            source_ip_types = ["source_ipv4_address", "source_ipv6_address"]
            for ip_type in source_ip_types:
                if ip_type in signature_groups and ip_type in data_item:
                    ip_sigs = signature_groups[ip_type]
                    self.logger.debug(
                        f"{LOG_PREFIX} Checking {ip_type} with {len(ip_sigs)} signatures"
                    )

                    for sig in ip_sigs:
                        filtered_data = {ip_type: data_item[ip_type]}
                        if detection_helper.match_alert_elements([sig], filtered_data):
                            self.logger.debug(
                                f"{LOG_PREFIX} ✓ {ip_type} signature matched: {sig['value']}"
                            )
                            source_ip_match = True
                            break

                    if source_ip_match:
                        break

            target_ip_types = ["target_ipv4_address", "target_ipv6_address"]
            for ip_type in target_ip_types:
                if ip_type in signature_groups and ip_type in data_item:
                    ip_sigs = signature_groups[ip_type]
                    self.logger.debug(
                        f"{LOG_PREFIX} Checking {ip_type} with {len(ip_sigs)} signatures"
                    )

                    for sig in ip_sigs:
                        filtered_data = {ip_type: data_item[ip_type]}
                        if detection_helper.match_alert_elements([sig], filtered_data):
                            self.logger.debug(
                                f"{LOG_PREFIX} ✓ {ip_type} signature matched: {sig['value']}"
                            )
                            target_ip_match = True
                            break

                    if target_ip_match:
                        break

            has_source_sigs = any(t in signature_groups for t in source_ip_types)
            has_target_sigs = any(t in signature_groups for t in target_ip_types)

            self.logger.debug(
                f"{LOG_PREFIX} Match results - Parent: {parent_process_match}, "
                f"Source IP: {source_ip_match} (required: {has_source_sigs}), "
                f"Target IP: {target_ip_match} (required: {has_target_sigs})"
            )

            if not parent_process_match:
                return False

            if has_source_sigs and has_target_sigs:
                result = source_ip_match or target_ip_match
            elif has_source_sigs:
                result = source_ip_match
            elif has_target_sigs:
                result = target_ip_match
            else:
                result = True

            self.logger.debug(f"{LOG_PREFIX} Final match result: {result}")
            return result

        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Error in detection_helper matching: {e}")
            return False

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
