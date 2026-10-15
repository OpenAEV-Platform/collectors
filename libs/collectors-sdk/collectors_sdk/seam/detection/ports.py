"""Detection port: the behaviour the public detection helper expects from the core."""

from typing import Any, Callable, Protocol, runtime_checkable

__all__ = ["AlertMatchingPort"]


@runtime_checkable
class AlertMatchingPort(Protocol):
    """Matches collected alert data against inject signatures."""

    def match_alert_element_fuzzy(
        self, logger: Any, signature_value: Any, alert_values: Any, fuzzy_scoring: Any
    ) -> bool:
        """Whether one alert value is a fuzzy match of the signature value."""

    def match_original(
        self,
        signatures: Any,
        alert_data: Any,
        relevant_signatures_types: Any,
        fuzzy_match: Callable[..., bool],
    ) -> bool:
        """Whether every relevant signature matches its alert data (simple or
        fuzzy, as the alert data declares)."""

    def match_command_line(
        self, signatures: Any, alert_data: Any, decode_value: Callable[[Any], Any]
    ) -> bool:
        """Whether a (decoded) command-line signature contains alert process data."""

    def decode_value(self, logger: Any, signature_value: Any) -> Any:
        """The value, base64-decoded when it is base64."""

    def is_base64_encoded(self, str_maybe_base64: Any) -> bool:
        """Whether the value looks base64-encoded."""
