"""Generic Expectation Handler."""

import logging
from typing import Any

from pyoaev.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    DetectionExpectation, PreventionExpectation)
from pyoaev.helpers import \
    OpenAEVDetectionHelper  # type: ignore[import-untyped]
from pyoaev.signatures.types import \
    SignatureTypes  # type: ignore[import-untyped]

from .exception import ExpectationHandlerError
from .expectation_service_provider import ExpectationServiceProvider
from .models import ExpectationResult
from .signature_registry import ExpectationHandlerType, get_registry

LOG_PREFIX = "[CollectorExpectationHandler]"


class GenericExpectationHandler:
    """Generic expectation handler that delegates to service providers.

    This handler is completely agnostic to the specific use case and
    delegates all processing logic to the injected service provider.
    """

    def __init__(self, service_provider: ExpectationServiceProvider) -> None:
        """Initialize the generic handler.

        Args:
            service_provider: Service provider implementing business logic.

        """
        self.logger = logging.getLogger(__name__)
        self.service_provider = service_provider

        self.logger.debug(f"{LOG_PREFIX} Initializing generic expectation handler")
        self._register_with_registry()
        self.logger.info(
            f"{LOG_PREFIX} Generic expectation handler initialized successfully"
        )

    def _register_with_registry(self) -> None:
        """Register handler capabilities with the signature registry.

        Registers detection and prevention handlers with the signature registry
        for all supported signature types from the service provider.

        Raises:
            Exception: If registration with registry fails.

        """
        try:
            registry = get_registry()
            supported_signatures = self.service_provider.get_supported_signatures()

            registry.register_handler(
                handler_type=ExpectationHandlerType.DETECTION,
                handler_func=self.handle_expectation,
                signature_types=supported_signatures,
            )

            registry.register_handler(
                handler_type=ExpectationHandlerType.PREVENTION,
                handler_func=self.handle_expectation,
                signature_types=supported_signatures,
            )

            self.logger.info(
                f"{LOG_PREFIX} Registered handler for {len(supported_signatures)} signature types: {[sig.value for sig in supported_signatures]}"
            )

        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Failed to register handler with registry: {e}"
            )
            raise

    def handle_expectation(
        self,
        expectation: Any,
        detection_helper: OpenAEVDetectionHelper,
    ) -> ExpectationResult:
        """Handle an expectation by delegating to the service provider.

        Args:
            expectation: The expectation to process.
            detection_helper: OpenAEV detection helper instance.

        Returns:
            ExpectationResult containing processing results.

        Raises:
            Exception: If expectation handling fails.

        """
        expectation_id = (
            str(expectation.inject_expectation_id)
            if hasattr(expectation, "inject_expectation_id")
            else "unknown"
        )

        try:
            if isinstance(expectation, DetectionExpectation):
                self.logger.debug(
                    f"{LOG_PREFIX} Processing detection expectation: {expectation_id}"
                )
                result = self.service_provider.handle_detection_expectation(
                    expectation, detection_helper
                )
            elif isinstance(expectation, PreventionExpectation):
                self.logger.debug(
                    f"{LOG_PREFIX} Processing prevention expectation: {expectation_id}"
                )
                result = self.service_provider.handle_prevention_expectation(
                    expectation, detection_helper
                )
            else:
                self.logger.warning(
                    f"{LOG_PREFIX} Unsupported expectation type for {expectation_id}: {type(expectation)}"
                )
                result = ExpectationResult(
                    expectation_id=expectation_id,
                    is_valid=False,
                    expectation=expectation,
                    error_message="Unsupported expectation type",
                )

            return result

        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Error handling expectation {expectation_id}: {e}"
            )
            raise

    def handle_batch_expectations(
        self,
        expectations: list[Any],
        detection_helper: OpenAEVDetectionHelper,
    ) -> list[ExpectationResult]:
        """Handle a batch of expectations by delegating to the service provider.

        Post-processes results to ensure completeness by filling in missing
        expectation IDs and expectation objects.

        Args:
            expectations: List of expectations to process.
            detection_helper: OpenAEV detection helper instance.

        Returns:
            List of ExpectationResult objects.

        Raises:
            ExpectationHandlerError: If batch processing fails.

        """
        try:
            self.logger.info(
                f"{LOG_PREFIX} Starting batch processing of {len(expectations)} expectations"
            )

            results = self.service_provider.handle_batch_expectations(
                expectations, detection_helper
            )

            # Post-process results to ensure completeness
            self.logger.debug(f"{LOG_PREFIX} Post-processing batch results...")
            for i, result in enumerate(results):
                if result.expectation is None and i < len(expectations):
                    result.expectation = expectations[i]
                if not result.expectation_id and result.expectation:
                    result.expectation_id = str(
                        result.expectation.inject_expectation_id
                    )

            valid_count = sum(1 for r in results if r.is_valid)
            invalid_count = len(results) - valid_count

            self.logger.info(
                f"{LOG_PREFIX} Batch processing completed: {valid_count} valid, {invalid_count} invalid out of {len(results)} total"
            )

            return results

        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Batch processing failed: {e}")
            raise ExpectationHandlerError(f"Error in batch processing: {e}") from e

    def get_supported_signatures(self) -> list[SignatureTypes]:
        """Get supported signature types from service provider.

        Returns:
            List of SignatureTypes supported by the service provider.

        """
        signatures = self.service_provider.get_supported_signatures()
        self.logger.debug(
            f"{LOG_PREFIX} Supported signatures: {[sig.value for sig in signatures]}"
        )
        return signatures
