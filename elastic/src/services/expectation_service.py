"""Elastic Security Expectation Service Provider.

This module contains all the Elastic Security-specific logic for handling expectations.
It implements the service provider protocol and defines which signatures to support,
how to fetch data, and how to process expectations.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from pyoaev.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.helpers import OpenAEVDetectionHelper  # type: ignore[import-untyped]
from pyoaev.signatures.types import SignatureTypes  # type: ignore[import-untyped]

from ..models.configs.config_loader import ConfigLoader
from . import signature_compat  # noqa: F401  installs the fail-soft enum shim
from .client_api import ElasticClientAPI
from .converter import Converter
from .exception import (
    LEAVE_PENDING_ERRORS,
    ElasticAPIError,
    ElasticConfigurationError,
    ElasticDataConversionError,
    ElasticExpectationError,
    ElasticMatchingError,
    ElasticNetworkError,
    ElasticNoAlertsFoundError,
    ElasticNoMatchingAlertsError,
    ElasticServiceError,
    ElasticUngradableError,
    ElasticValidationError,
)

if TYPE_CHECKING:  # avoid a runtime services->collector import cycle
    from ..collector.models import ExpectationResult

LOG_PREFIX = "[ElasticExpectationService]"


class ElasticExpectationService:
    """Elastic Security-specific service provider for expectation handling.

    This class contains all the business logic specific to Elastic Security:
    - Which signature types to support (only IPV4/6 addresses)
    - How to fetch data from Elastic Security
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
        """Initialize the Elastic Security service provider.

        Args:
            config: Configuration loader instance for service settings.

        Raises:
            ElasticValidationError: If config is None.
            ElasticConfigurationError: If service components initialization fails.

        """
        if config is None:
            raise ElasticValidationError("Config is required for expectation service")

        self.logger = logging.getLogger(__name__)
        self.config = config

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Initializing Elastic Security service components..."
            )
            self.client_api = ElasticClientAPI(config)
            self.converter = Converter()
            # Deterministic per-inject correlation requires a process-events
            # index for the implant-marker drilldown. When it is absent (SIEM
            # only), we must fall back to IP + time for implant expectations
            # instead of strictly rejecting markerless endpoint alerts (which
            # would false-negative every implant inject).
            self.drilldown_enabled = bool(
                getattr(self.client_api, "events_index", None)
            )
            if not self.drilldown_enabled:
                self.logger.warning(
                    f"{LOG_PREFIX} No events index configured (ELASTIC_EVENTS_INDEX "
                    "empty): implant-marker drilldown disabled; implant injects "
                    "fall back to IP + time correlation (lower confidence, cannot "
                    "dissociate same-host injects)."
                )
            self.logger.info(
                f"{LOG_PREFIX} Elastic Security expectation service initialized successfully"
            )
        except ElasticValidationError, ElasticConfigurationError:
            raise
        except Exception as e:
            raise ElasticConfigurationError(
                f"Failed to initialize Elastic Security service components: {e}"
            ) from e

        if (
            hasattr(config, "elastic")
            and hasattr(config.elastic, "time_window")
            and config.elastic.time_window
        ):
            self.time_window = config.elastic.time_window
            self.logger.debug(
                f"{LOG_PREFIX} Using configured time window: {self.time_window}"
            )
        else:
            self.time_window = timedelta(hours=1)
            self.logger.warning(
                f"{LOG_PREFIX} No time_window configured, using default 1 hour"
            )

        if hasattr(config, "elastic"):
            self.max_retry = getattr(config.elastic, "max_retry", 3)
            self.offset = getattr(
                config.elastic, "offset", timedelta(seconds=30)
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
            ElasticExpectationError: If batch processing fails.

        """
        if not expectations:
            self.logger.info(f"{LOG_PREFIX} No expectations to process")
            return []

        # New cycle: clear the recovered-marker cache so pid-based seeds cannot
        # go stale across cycles (markers are then reused across alerts, retries
        # and expectations within this cycle).
        self.client_api.reset_marker_cache()

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

                except LEAVE_PENDING_ERRORS as e:
                    # Transient outage (SIEM/API unreachable, auth failure) or an
                    # ungradable expectation (no usable signature). We can assert
                    # NEITHER Detected NOR Not Detected, so LEAVE IT PENDING:
                    # omit it from the returned results and the server re-serves
                    # it next cycle. This avoids recording a false 'Not Detected'
                    # for a mere outage - a genuine "queried, nothing matched"
                    # still raises ElasticNoMatching/NoAlerts (below) -> graded.
                    self.logger.warning(
                        f"{LOG_PREFIX} Leaving expectation {expectation_id} PENDING "
                        f"(not graded this cycle): {e}"
                    )
                    continue
                except ElasticServiceError as e:
                    self.logger.warning(
                        f"{LOG_PREFIX} Elastic Security service error for expectation {expectation_id}: {e}"
                    )
                    result = self._create_error_result_object(e, expectation)
                except Exception as e:
                    self.logger.error(
                        f"{LOG_PREFIX} Unexpected error processing expectation {expectation_id}: {e}"
                    )
                    result = self._create_error_result_object(
                        ElasticExpectationError(f"Unexpected error: {e}"),
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
            raise ElasticExpectationError(
                f"Error in handle_batch_expectations: {e}"
            ) from e

    def process_expectation(
        self,
        expectation: DetectionExpectation | PreventionExpectation,
        detection_helper: OpenAEVDetectionHelper,
    ) -> ExpectationResult:
        """Process a single expectation based on its type.

        Args:
            expectation: The expectation to process (Detection only for Elastic Security).
            detection_helper: OpenAEV detection helper instance.

        Returns:
            ExpectationResult containing the processing outcome.

        Raises:
            ElasticExpectationError: If expectation type is unsupported.

        """
        expectation_id = str(expectation.inject_expectation_id)

        if isinstance(expectation, DetectionExpectation):
            self.logger.debug(
                f"{LOG_PREFIX} Processing detection expectation: {expectation_id}"
            )
            return self.handle_detection_expectation(expectation, detection_helper)
        elif isinstance(expectation, PreventionExpectation):
            self.logger.warning(
                f"{LOG_PREFIX} Elastic Security service warning for expectation {expectation_id}: Elastic Security only supports DetectionExpectations, not PreventionExpectations, marking them as invalid"
            )
            from ..collector.models import ExpectationResult

            return ExpectationResult(
                expectation_id=expectation_id,
                is_valid=False,
                expectation=expectation,
                error_message="Elastic Security only supports DetectionExpectations, not PreventionExpectations",
            )
        else:
            self.logger.error(
                f"{LOG_PREFIX} Unsupported expectation type for {expectation_id}: {type(expectation).__name__}"
            )
            raise ElasticExpectationError(
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

        Since Elastic Security only supports detection, this method logs a warning
        and returns an invalid result instead of throwing an error.

        Args:
            expectation: The prevention expectation to process.
            detection_helper: OpenAEV detection helper instance.

        Returns:
            ExpectationResult indicating that prevention is not supported.

        """
        expectation_id = str(expectation.inject_expectation_id)
        self.logger.warning(
            f"{LOG_PREFIX} Elastic Security service error for expectation {expectation_id}: Elastic Security only supports DetectionExpectations, not PreventionExpectations"
        )
        from ..collector.models import ExpectationResult

        return ExpectationResult(
            expectation_id=expectation_id,
            is_valid=False,
            expectation=expectation,
            error_message="Elastic Security only supports DetectionExpectations, not PreventionExpectations",
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
            ElasticExpectationError: If expectation processing fails.

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

            # No usable signature (e.g. only unknown / unsupported types after
            # normalization): we can assert neither Detected nor Not Detected, so
            # leave it PENDING rather than fetch (which would raise) or grade a
            # false 'Not Detected'.
            if not search_signatures:
                raise ElasticUngradableError(
                    f"expectation {expectation_id} has no usable signature "
                    "(only unknown/unsupported types); leaving pending"
                )

            self.logger.debug(
                f"{LOG_PREFIX} Fetching Elastic Security data for {expectation_type} expectation..."
            )

            # Retry until an alert that actually MATCHES this expectation appears
            # (or the budget is exhausted), so detection latency is absorbed even
            # when unrelated alerts from a concurrent inject are already present -
            # otherwise a non-empty-but-non-matching fetch would end the retries
            # and mark the expectation Not Detected prematurely.
            def _match_check(alerts: list[Any]) -> bool:
                try:
                    candidate = self.converter.convert_data_to_oaev_data(alerts)
                    return self._any_match(
                        candidate, matching_signatures, detection_helper
                    )
                except Exception:  # best-effort: never let the predicate abort retries
                    return False

            elastic_data = self.client_api.fetch_with_retry(
                search_signatures,
                expectation_type,
                self.max_retry,
                int(self.offset),
                match_check=_match_check,
            )
            self.logger.debug(
                f"{LOG_PREFIX} Fetched {len(elastic_data)} data items from Elastic Security"
            )

            self.logger.debug(
                f"{LOG_PREFIX} Converting Elastic Security data to OAEV format..."
            )
            oaev_data = self.converter.convert_data_to_oaev_data(elastic_data)
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
            ElasticServiceError,
            ElasticAPIError,
            ElasticNetworkError,
            ElasticDataConversionError,
        ):
            raise
        except Exception as e:
            raise ElasticExpectationError(
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
            ElasticExpectationError: If signature extraction fails.

        """
        try:
            # Normalize alternate / agentless vocabularies onto the canonical
            # types the pipeline understands (source_ipv4 -> source_ipv4_address,
            # start_time -> start_date, ...), so NetExec/agentless injects drive
            # search + matching instead of being silently dropped.
            all_signatures = [
                {
                    "type": signature_compat.CANONICAL_ALIASES.get(
                        sig.type.value, sig.type.value
                    ),
                    "value": sig.value,
                }
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
            raise ElasticExpectationError(
                f"Failed to extract signatures from expectation: {e}"
            ) from e

    def _any_match(
        self,
        oaev_data: list[dict[str, Any]],
        matching_signatures: list[dict[str, str]],
        detection_helper: OpenAEVDetectionHelper,
    ) -> bool:
        """Return whether any data item matches the expectation (no raising).

        A lightweight, side-effect-free mirror of ``_match`` used as the retry
        predicate: it tells the fetch loop whether a matching alert has appeared
        yet, so retries continue through detection latency without prematurely
        settling on a non-matching batch.
        """
        if not oaev_data:
            return False
        expectation_expects_parent = any(
            sig.get("type") == "parent_process_name" for sig in matching_signatures
        )
        for data_item in oaev_data:
            available = [s for s in matching_signatures if s["type"] in data_item]
            if not available:
                continue
            try:
                if self._match_with_detection_helper(
                    available,
                    data_item,
                    detection_helper,
                    expectation_expects_parent=expectation_expects_parent,
                ):
                    return True
            except Exception:  # noqa: S112  best-effort predicate
                continue
        return False

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
            ElasticNoAlertsFoundError: If no data available for matching.
            ElasticNoMatchingAlertsError: If no matching alerts found.
            ElasticMatchingError: If matching process fails.

        """
        try:
            if not oaev_data:
                self.logger.debug(f"{LOG_PREFIX} No OAEV data available for matching")
                raise ElasticNoAlertsFoundError("No data available for matching")

            self.logger.debug(
                f"{LOG_PREFIX} Attempting to match {len(oaev_data)} data items against {len(matching_signatures)} signatures"
            )

            # Whether this expectation carries an implant marker at all. Drives
            # deterministic correlation (see _match_with_detection_helper).
            expectation_expects_parent = any(
                sig.get("type") == "parent_process_name" for sig in matching_signatures
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
                            available_signatures,
                            data_item,
                            detection_helper,
                            expectation_expects_parent=expectation_expects_parent,
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
                        raise ElasticNoMatchingAlertsError() from e
                else:
                    self.logger.debug(
                        f"{LOG_PREFIX} Data item {i + 1} has no available signatures to match against"
                    )

            self.logger.info(
                f"{LOG_PREFIX} No matching alerts found after checking {len(oaev_data)} data items"
            )
            raise ElasticNoMatchingAlertsError()

        except (
            ElasticServiceError,
            ElasticNoAlertsFoundError,
            ElasticNoMatchingAlertsError,
        ):
            raise
        except Exception as e:
            raise ElasticMatchingError() from e

    def _match_with_detection_helper(  # noqa: C901
        self,
        signatures: list[dict[str, str]],
        data_item: dict[str, Any],
        detection_helper: OpenAEVDetectionHelper,
        expectation_expects_parent: bool = False,
    ) -> bool:
        """Match signatures using detection_helper with proper OR logic.

        Args:
            signatures: List of signature dictionaries.
            data_item: OAEV data item to match against.
            detection_helper: OpenAEV detection helper instance.
            expectation_expects_parent: Whether the expectation carries an
                implant marker (parent_process_name), i.e. the inject ran on an
                OpenAEV implant/agent. Such expectations are correlated
                deterministically around the implant marker (see below).

        Returns:
            True if matching succeeds, False otherwise.

        Correlation model (implant vs agentless):

        * Implant inject (``expectation_expects_parent``): the implant marker is
          the deterministic key. An alert whose drilldown recovered a marker
          must match THIS inject's marker. An **endpoint** alert (process
          context) that carries no matching marker is rejected - no IP
          substitute - so an unrelated technique on the same host is never
          cross-attributed. Only **network** telemetry (Suricata/Zeek), which
          cannot carry an implant marker, falls back to source/target IP + time.
        * Agentless inject (no ``parent_process_name`` signature): there is a 0%
          chance of an implant marker on the endpoints, so correlation is
          source/target IP + time directly.

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
            has_parent_sigs = "parent_process_name" in signature_groups

            self.logger.debug(
                f"{LOG_PREFIX} Match results - Parent: {parent_process_match} "
                f"(present: {has_parent_sigs}), "
                f"Source IP: {source_ip_match} (required: {has_source_sigs}), "
                f"Target IP: {target_ip_match} (required: {has_target_sigs})"
            )

            # Deterministic correlation for implant injects.
            if expectation_expects_parent:
                # The alert's drilldown recovered a marker: it must be THIS
                # inject's marker (a different inject/technique on the same host
                # carries a different marker and is rejected above at line ~617).
                if has_parent_sigs:
                    self.logger.debug(
                        f"{LOG_PREFIX} Final match result (implant marker): "
                        f"{parent_process_match}"
                    )
                    return parent_process_match

                # No marker on the alert. If it is endpoint/process telemetry it
                # SHOULD have carried the marker: reject it (no IP substitute) so
                # an unrelated same-host alert is never cross-attributed - but
                # ONLY when the drilldown is actually available. With no events
                # index there is no way to recover a marker, so rejecting would
                # false-negative every implant inject; degrade to IP + time.
                if data_item.get("_endpoint_context") and self.drilldown_enabled:
                    self.logger.debug(
                        f"{LOG_PREFIX} Endpoint alert without implant marker "
                        f"-> reject (deterministic, no IP substitute)"
                    )
                    return False

                # Network telemetry (Suricata/Zeek) cannot carry an implant
                # marker: accept it via source/target IP + time below (lower
                # confidence, cannot dissociate same-host injects).
                self.logger.debug(
                    f"{LOG_PREFIX} Network telemetry for implant inject "
                    f"-> IP + time fallback"
                )

            if has_source_sigs and has_target_sigs:
                result = source_ip_match or target_ip_match
            elif has_source_sigs:
                result = source_ip_match
            elif has_target_sigs:
                result = target_ip_match
            else:
                result = True

            self.logger.debug(
                f"{LOG_PREFIX} Final match result (ip-fallback): {result}"
            )
            return result

        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Error in detection_helper matching: {e}")
            return False

    def _create_error_result(
        self,
        error: ElasticServiceError,
        expectation: DetectionExpectation | None = None,
    ) -> dict[str, Any]:
        """Create an error result dictionary from a Elastic Security service error.

        Args:
            error: The Elastic Security service error that occurred.
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
        error: ElasticServiceError,
        expectation: DetectionExpectation | None = None,
    ) -> ExpectationResult:
        """Create an ExpectationResult object from a Elastic Security service error.

        Args:
            error: The Elastic Security service error that occurred.
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

        from ..collector.models import ExpectationResult

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
        from ..collector.models import ExpectationResult

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
            "service_name": "Elastic Security",
            "supported_signatures": [sig.value for sig in self.SUPPORTED_SIGNATURES],
            "supports_detection": True,
            "supports_prevention": False,
            "description": f"Elastic Security expectation validation service ({len(self.SUPPORTED_SIGNATURES)} signature types, detection only)",
        }
        self.logger.debug(f"{LOG_PREFIX} Service info: {info}")
        return info
