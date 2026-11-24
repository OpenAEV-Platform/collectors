"""Expectation matching: alerts against an expectation's signatures."""

from typing import Any, Callable

from collectors_sdk.seam.expectations import ExpectationSignature
from thefuzz import fuzz
from xtm_oaev_sdk import MatchTypes

__all__ = ["ExpectationMatcher"]


class ExpectationMatcher:
    """Implements ``ExpectationMatchingPort``."""

    def match_alert(
        self,
        signatures: list[ExpectationSignature],
        relevant_signature_types: list[Any],
        alert_data: Any,
        match_fuzzy: Callable[..., bool],
        match_simple: Callable[..., bool],
    ) -> bool:
        relevant_expectation_signatures = [
            signature
            for signature in signatures
            if signature.type in [type.label for type in relevant_signature_types]
        ]
        if not any(relevant_expectation_signatures):
            return False

        for relevant_expectation_signature in relevant_expectation_signatures:
            if not (
                alert_signature_for_type := alert_data.get(
                    relevant_expectation_signature.type.value
                )
            ):
                return False

            if alert_signature_for_type[
                "type"
            ] == MatchTypes.MATCH_TYPE_FUZZY and not match_fuzzy(
                alert_signature_for_type["data"],
                relevant_expectation_signature.value,
                alert_signature_for_type["score"],
            ):
                return False
            if alert_signature_for_type[
                "type"
            ] == MatchTypes.MATCH_TYPE_SIMPLE and not match_simple(
                alert_signature_for_type["data"], relevant_expectation_signature.value
            ):
                return False

        return True

    def match_fuzzy(self, tested: list[str], reference: str, threshold: int) -> bool:
        actual_tested = [tested] if isinstance(tested, str) else tested
        for value in actual_tested:
            ratio = fuzz.ratio(value, reference)
            if ratio >= threshold:
                return True
        return False
