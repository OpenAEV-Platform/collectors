"""Signature-to-alert matching engine for detection collectors.

Compares platform-generated execution signatures against alert data
from security tools to determine detection/prevention matches.
"""

from __future__ import annotations

import base64
import logging
import re
from typing import Any, Dict, List, Sequence

from thefuzz import fuzz

_BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


def _is_base64_encoded(value: str) -> bool:
    """Check if a string appears to be valid base64-encoded data."""
    return len(value) % 4 == 0 and bool(_BASE64_PATTERN.match(value))


def _decode_value(value: str, logger: logging.Logger | None = None) -> str:
    """Decode a base64-encoded signature value, returning as-is if not encoded."""
    if _is_base64_encoded(value):
        try:
            return base64.b64decode(value).decode("utf-8")
        except Exception as e:
            if logger:
                logger.error(str(e))
    return value


class SignatureMatcher:
    """Matches execution signatures against alert data from security tools.

    This is the core detection logic used by all detection/prevention collectors.
    It supports fuzzy matching (via thefuzz) and simple string containment.

    :param relevant_signature_types: signature type identifiers this collector cares about.
    :param logger: optional logger for match diagnostics.
    """

    def __init__(
        self,
        relevant_signature_types: Sequence[str],
        logger: logging.Logger | None = None,
    ) -> None:
        self.relevant_signature_types = list(relevant_signature_types)
        self.logger = logger or logging.getLogger(__name__)

    def match(self, signatures: List[Dict[str, Any]], alert_data: Dict[str, Any]) -> bool:
        """Check if signatures match the alert data.

        Tries the standard per-type matching first, then falls back to
        command-line heuristic matching.

        :param signatures: list of signature dicts with 'type' and 'value' keys.
        :param alert_data: dict mapping signature types to match criteria.
        :return: True if all relevant signatures match.
        """
        return self._match_by_type(signatures, alert_data) or self._match_command_line(
            signatures, alert_data
        )

    def match_fuzzy(
        self, signature_value: str, alert_values: List[str], fuzzy_scoring: int
    ) -> bool:
        """Fuzzy-match a single signature value against a list of alert values.

        :param signature_value: the expected signature value.
        :param alert_values: candidate values from the alert.
        :param fuzzy_scoring: minimum fuzz.ratio score to consider a match.
        :return: True if any alert value scores above the threshold.
        """
        for alert_value in alert_values:
            self.logger.info(
                "Comparing alert value (%s, %s)", alert_value, signature_value
            )
            ratio = fuzz.ratio(alert_value, signature_value)
            if ratio > fuzzy_scoring:
                self.logger.info("MATCHING! (score: %d)", ratio)
                return True
        return False

    def _match_by_type(
        self, signatures: List[Dict[str, Any]], alert_data: Dict[str, Any]
    ) -> bool:
        """Match relevant signatures against typed alert data entries."""
        relevant_signatures = [
            s for s in signatures if s["type"] in self.relevant_signature_types
        ]

        if not relevant_signatures:
            return False

        matching_count = 0
        for signature in relevant_signatures:
            sig_type = signature["type"]
            if sig_type not in alert_data:
                continue
            alert_entry = alert_data[sig_type]
            matched = False

            if alert_entry["type"] == "fuzzy":
                matched = self.match_fuzzy(
                    signature["value"],
                    alert_entry["data"],
                    alert_entry["score"],
                )
            elif alert_entry["type"] == "simple":
                matched = signature["value"] in str(alert_entry["data"])

            if matched:
                matching_count += 1

        return len(relevant_signatures) == matching_count

    def _match_command_line(
        self, signatures: List[Dict[str, Any]], alert_data: Dict[str, Any]
    ) -> bool:
        """Fallback: match command_line signatures against process/file alert data."""
        command_line_signatures = [
            s for s in signatures if s.get("type") == "command_line"
        ]
        if not command_line_signatures:
            return False

        key_types = ["command_line", "process_name", "file_name"]
        alert_entries = [alert_data.get(key) for key in key_types if key in alert_data]

        for signature in command_line_signatures:
            signature_value = _decode_value(signature["value"], self.logger).strip().lower()
            for entry in alert_entries:
                trimmed_lowered = [s.strip().lower() for s in entry["data"]]
                if any(data in signature_value for data in trimmed_lowered):
                    return True
        return False
