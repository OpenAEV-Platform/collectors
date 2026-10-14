"""Alert-element detection: match collected alert data against inject signatures."""

import base64
import re

from thefuzz import fuzz

__all__ = ["OpenAEVDetectionHelper"]


class OpenAEVDetectionHelper:
    def __init__(self, logger, relevant_signatures_types) -> None:
        self.logger = logger
        self.relevant_signatures_types = relevant_signatures_types

    def match_alert_element_fuzzy(self, signature_value, alert_values, fuzzy_scoring):
        for alert_value in alert_values:
            self.logger.info(
                "Comparing alert value (" + alert_value + ", " + signature_value + ")"
            )
            ratio = fuzz.ratio(alert_value, signature_value)
            if ratio > fuzzy_scoring:
                self.logger.info("MATCHING! (score: " + str(ratio) + ")")
                return True
        return False

    def match_alert_elements(self, signatures, alert_data):
        return self._match_alert_elements_original(
            signatures, alert_data
        ) or self._match_alert_elements_for_command_line(signatures, alert_data)

    def _match_alert_elements_original(self, signatures, alert_data):
        # Example for alert_data
        # {"process_name": {"list": ["xx", "yy"], "fuzzy": 90}}
        relevant_signatures = [
            s for s in signatures if s["type"] in self.relevant_signatures_types
        ]

        # Matching logics
        signatures_number = len(relevant_signatures)
        matching_number = 0
        for signature in relevant_signatures:
            alert_data_for_signature = alert_data[signature["type"]]
            signature_result = False
            if alert_data_for_signature["type"] == "fuzzy":
                signature_result = self.match_alert_element_fuzzy(
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

    def _match_alert_elements_for_command_line(self, signatures, alert_data):
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
            signature_value = self._decode_value(signature["value"]).strip().lower()
            for alert_data in alert_datas:
                trimmed_lowered_datas = [s.strip().lower() for s in alert_data["data"]]
                signature_result = any(
                    data in signature_value for data in trimmed_lowered_datas
                )
            if signature_result:
                return True
        return False

    def _decode_value(self, signature_value):
        if _is_base64_encoded(signature_value):
            try:
                decoded_bytes = base64.b64decode(signature_value)
                decoded_str = decoded_bytes.decode("utf-8")
                return decoded_str
            except Exception as e:
                self.logger.error(str(e))
        else:
            return signature_value


def _is_base64_encoded(str_maybe_base64):
    # Check if the length is a multiple of 4 and matches the Base64 character set
    base64_pattern = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
    return len(str_maybe_base64) % 4 == 0 and bool(
        base64_pattern.match(str_maybe_base64)
    )
