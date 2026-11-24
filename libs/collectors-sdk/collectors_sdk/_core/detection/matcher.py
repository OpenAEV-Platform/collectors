"""Alert matching: compare collected alert data with inject signatures."""

import base64
import re
from typing import Any, Callable

from thefuzz import fuzz

__all__ = ["AlertMatcher"]


class AlertMatcher:
    """Implements ``AlertMatchingPort``."""

    def match_alert_element_fuzzy(
        self, logger: Any, signature_value: Any, alert_values: Any, fuzzy_scoring: Any
    ) -> bool:
        for alert_value in alert_values:
            logger.info(
                "Comparing alert value (" + alert_value + ", " + signature_value + ")"
            )
            ratio = fuzz.ratio(alert_value, signature_value)
            if ratio > fuzzy_scoring:
                logger.info("MATCHING! (score: " + str(ratio) + ")")
                return True
        return False

    def match_original(
        self,
        signatures: Any,
        alert_data: Any,
        relevant_signatures_types: Any,
        fuzzy_match: Callable[..., bool],
    ) -> bool:
        relevant_signatures = [
            s for s in signatures if s["type"] in relevant_signatures_types
        ]

        # Matching logics
        signatures_number = len(relevant_signatures)
        matching_number = 0
        for signature in relevant_signatures:
            alert_data_for_signature = alert_data[signature["type"]]
            signature_result = False
            if alert_data_for_signature["type"] == "fuzzy":
                signature_result = fuzzy_match(
                    signature["value"],
                    alert_data_for_signature["data"],
                    alert_data_for_signature["score"],
                )
            elif alert_data_for_signature["type"] == "simple":
                signature_result = signature["value"] in str(
                    alert_data_for_signature["data"]
                )

            if signature_result:
                matching_number = matching_number + 1

        if signatures_number == matching_number:
            return True
        return False

    def match_command_line(
        self, signatures: Any, alert_data: Any, decode_value: Callable[[Any], Any]
    ) -> bool:
        command_line_signatures = [
            signature
            for signature in signatures
            if signature.get("type") == "command_line"
        ]
        if len(command_line_signatures) == 0:
            return False
        key_types = ["command_line", "process_name", "file_name"]
        alert_datas = [alert_data.get(key) for key in key_types if key in alert_data]
        for signature in command_line_signatures:
            signature_result = False
            signature_value = decode_value(signature["value"]).strip().lower()
            for alert_data in alert_datas:
                trimmed_lowered_datas = [s.strip().lower() for s in alert_data["data"]]
                signature_result = any(
                    data in signature_value for data in trimmed_lowered_datas
                )
            if signature_result:
                return True
        return False

    def decode_value(self, logger: Any, signature_value: Any) -> Any:
        if self.is_base64_encoded(signature_value):
            try:
                decoded_bytes = base64.b64decode(signature_value)
                decoded_str = decoded_bytes.decode("utf-8")
                return decoded_str
            except Exception as e:
                logger.error(str(e))
        else:
            return signature_value

    def is_base64_encoded(self, str_maybe_base64: Any) -> bool:
        # Check if the length is a multiple of 4 and matches the Base64 character set
        base64_pattern = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
        return len(str_maybe_base64) % 4 == 0 and bool(
            base64_pattern.match(str_maybe_base64)
        )
