"""Expectation ports: the behaviour the public expectations expect from the core."""

from typing import Any, Callable, Protocol, runtime_checkable

from collectors_sdk.seam.expectations.models import ExpectationSignature

__all__ = ["ExpectationMatchingPort", "ExpectationUpdatePort"]


@runtime_checkable
class ExpectationMatchingPort(Protocol):
    """Matches alert data against an expectation's signatures."""

    def match_alert(
        self,
        signatures: list[ExpectationSignature],
        relevant_signature_types: list[Any],
        alert_data: Any,
        match_fuzzy: Callable[..., bool],
        match_simple: Callable[..., bool],
    ) -> bool:
        """Whether the alert matches every relevant signature."""

    def match_fuzzy(self, tested: list[str], reference: str, threshold: int) -> bool:
        """Whether any candidate reaches ``threshold`` similarity with ``reference``."""


@runtime_checkable
class ExpectationUpdatePort(Protocol):
    """Builds the outcome the platform records for an expectation."""

    def outcome(
        self,
        success: bool,
        sender_id: Any,
        metadata: Any,
        success_label: str,
        failure_label: str,
    ) -> dict[str, Any]:
        """``inject_expectation`` payload of an expectation update."""
