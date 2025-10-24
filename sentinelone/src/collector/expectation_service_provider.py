"""Protocol defining the interface for expectation service providers."""

from typing import Any, Protocol

from pyoaev.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.helpers import OpenAEVDetectionHelper  # type: ignore[import-untyped]
from pyoaev.signatures.types import SignatureTypes  # type: ignore[import-untyped]

from .models import ExpectationResult


class ExpectationServiceProvider(Protocol):
    """Protocol defining the interface for expectation service providers."""

    def get_supported_signatures(self) -> list[SignatureTypes]:
        """Get list of signature types this provider supports.

        Returns:
            List of SignatureTypes that this provider can handle.

        """
        ...

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
        ...

    def handle_prevention_expectation(
        self,
        expectation: PreventionExpectation,
        detection_helper: OpenAEVDetectionHelper,
    ) -> ExpectationResult:
        """Handle a prevention expectation.

        Args:
            expectation: The prevention expectation to process.
            detection_helper: OpenAEV detection helper instance.

        Returns:
            ExpectationResult containing the processing outcome.

        """
        ...

    def handle_batch_expectations(
        self, expectations: list[Any], detection_helper: OpenAEVDetectionHelper
    ) -> tuple[list[ExpectationResult], int]:
        """Handle a batch of expectations efficiently.

        Args:
            expectations: List of expectations to process in batch.
            detection_helper: OpenAEV detection helper instance.

        Returns:
            Tuple of (results, skipped_count) where:
            - results: List of ExpectationResult objects for processed expectations
            - skipped_count: Number of expectations skipped due to missing end_date

        """
        ...
