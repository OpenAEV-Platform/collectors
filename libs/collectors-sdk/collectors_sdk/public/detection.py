"""Detection adapter: match collected alert data against inject signatures.

The adapter delegates to the core implementation of the detection port.
"""

from collectors_sdk._core.detection import AlertMatcher
from collectors_sdk.seam.detection import AlertMatchingPort

__all__ = ["OpenAEVDetectionHelper"]

_matching: AlertMatchingPort = AlertMatcher()


class OpenAEVDetectionHelper:

    def __init__(self, logger, relevant_signatures_types) -> None:
        self.logger = logger
        self.relevant_signatures_types = relevant_signatures_types

    def match_alert_element_fuzzy(self, signature_value, alert_values, fuzzy_scoring):
        return _matching.match_alert_element_fuzzy(
            self.logger, signature_value, alert_values, fuzzy_scoring
        )

    def match_alert_elements(self, signatures, alert_data):
        return self._match_alert_elements_original(
            signatures, alert_data
        ) or self._match_alert_elements_for_command_line(signatures, alert_data)

    def _match_alert_elements_original(self, signatures, alert_data):
        # Example for alert_data
        # {"process_name": {"list": ["xx", "yy"], "fuzzy": 90}}
        return _matching.match_original(
            signatures,
            alert_data,
            self.relevant_signatures_types,
            self.match_alert_element_fuzzy,
        )

    def _match_alert_elements_for_command_line(self, signatures, alert_data):
        return _matching.match_command_line(signatures, alert_data, self._decode_value)

    def _decode_value(self, signature_value):
        return _matching.decode_value(self.logger, signature_value)


def _is_base64_encoded(str_maybe_base64):
    """Whether the value looks base64-encoded (legacy private helper)."""
    return _matching.is_base64_encoded(str_maybe_base64)
