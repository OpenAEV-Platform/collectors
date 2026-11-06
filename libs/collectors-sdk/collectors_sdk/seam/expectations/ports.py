"""Expectation ports: the behaviour the public expectations expect from the core."""

from typing import Any, Callable, Protocol, runtime_checkable

from collectors_sdk.seam.expectations.models import ExpectationSignature

__all__ = [
    "ExpectationApiProtocol",
    "ExpectationLoadingPort",
    "ExpectationMatchingPort",
    "ExpectationUpdatePort",
]


@runtime_checkable
class ExpectationApiProtocol(Protocol):
    """The platform API expectations are fetched from and reported to.

    The OpenAEV client's inject expectation manager (``api.inject_expectation``
    in pyoaev) implements it.
    """

    def expectations_assets_for_source(
        self, source_id: str, **kwargs: Any
    ) -> list[dict[str, Any]]:
        """Expectations still waiting for a result from ``source_id``."""

    def update(
        self,
        inject_expectation_id: str,
        inject_expectation: dict[str, Any],
        **kwargs: Any,
    ) -> Any:
        """Records the outcome of one expectation."""


@runtime_checkable
class ExpectationLoadingPort(Protocol):
    """Turns the platform expectation data into expectation models."""

    def models_for_source(
        self,
        api: ExpectationApiProtocol,
        source_id: str,
        detection: Callable[..., Any],
        prevention: Callable[..., Any],
        **kwargs: Any,
    ) -> list[Any]:
        """Models of the expectations waiting for ``source_id``, built with
        ``detection`` or ``prevention`` depending on their type."""


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
