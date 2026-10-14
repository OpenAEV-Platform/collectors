"""Inject expectations: the expected outcomes a collector checks alerts against."""

from enum import Enum
from typing import Any, List
from uuid import UUID

from pydantic import BaseModel, Field, field_validator
from thefuzz import fuzz
from xtm_oaev_sdk import MatchTypes, SignatureType, SignatureTypes

__all__ = [
    "DetectionExpectation",
    "Expectation",
    "ExpectationSignature",
    "ExpectationTypeEnum",
    "PreventionExpectation",
]


class ExpectationTypeEnum(str, Enum):
    """Types of Expectations"""

    Detection = "DETECTION"
    Prevention = "PREVENTION"
    Vulnerability = "VULNERABILITY"
    Other = "other"

    @classmethod
    def _missing_(cls, value):
        return cls.Other


class ExpectationSignature(BaseModel):
    """An expectation signature describes a known marker potentially
    found in alerting data in security software. For example, an
    expectation signature can be a process image name, a command
    line, or any other relevant piece of data.
    """

    type: SignatureTypes
    value: str


class Expectation(BaseModel):
    """An expectation represents an expected outcome of a BAS run.
    For example, in the case of running an attack command line, the
    expectation may be that security software has _detected_ it, while
    another expectation may be that the attack was _prevented_.
    """

    inject_expectation_id: UUID
    inject_expectation_signatures: List[ExpectationSignature] = Field(
        default_factory=list
    )

    success_label: str = "Success"
    failure_label: str = "Failure"

    @field_validator("inject_expectation_signatures", mode="before")
    @classmethod
    def _coerce_none_signatures_to_empty(cls, value: Any) -> Any:
        # The platform serializes this field as null when an expectation has no
        # signatures yet. Without this, a single such expectation raises a
        # ValidationError that aborts the whole batch fetch (collectors#490).
        return [] if value is None else value

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.__api_client = kw["api_client"]

    def update(self, success, sender_id, metadata):
        """Update the expectation object in OpenAEV with the supplied outcome.

        :param success: whether the expectation was fulfilled (true) or not (false)
        :type success: bool
        :param sender_id: identifier of the collector that is updating the expectation
        :type sender_id: string
        :param metadata: arbitrary dictionary of additional data relevant to updating the expectation
        :type metadata: dict[string,string]
        """
        self.__api_client.update(
            self.inject_expectation_id,
            inject_expectation={
                "collector_id": sender_id,
                "result": (self.success_label if success else self.failure_label),
                "is_success": success,
                "metadata": metadata,
            },
        )

    def match_alert(self, relevant_signature_types: list[SignatureType], alert_data):
        """Matches an alert's data against the current expectation signatures
        to see if the alert is relevant to the current expectation's inject,
        i.e. this alert was triggered by the execution of the inject to which
        belongs the expectation.

        :param relevant_signature_types: filter of signature types that we want to consider.
            Only the signature types listed in this collection may be checked for matching.
        :type relevant_signature_types: list[SignatureType]
        :param alert_data: list of possibly relevant markers found in an alert.
        :type alert_data: dict[SignatureTypes, dict]

        :return: whether the alert matches the expectation signatures or not.
        :rtype: bool
        """
        relevant_expectation_signatures = [
            signature
            for signature in self.inject_expectation_signatures
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
            ] == MatchTypes.MATCH_TYPE_FUZZY and not self.match_fuzzy(
                alert_signature_for_type["data"],
                relevant_expectation_signature.value,
                alert_signature_for_type["score"],
            ):
                return False
            if alert_signature_for_type[
                "type"
            ] == MatchTypes.MATCH_TYPE_SIMPLE and not self.match_simple(
                alert_signature_for_type["data"], relevant_expectation_signature.value
            ):
                return False

        return True

    @staticmethod
    def match_fuzzy(tested: list[str], reference: str, threshold: int):
        """Applies a fuzzy match against a known reference to a list of candidates

        :param tested: list of strings candidate for fuzzy matching
        :type tested: list[str]
        :param reference: the reference against which to try to fuzzy match
        :type reference: str
        :param threshold: string overlap percentage threshold above which to declare a match
        :type threshold: int

        :return: whether any of the candidate is a match against the reference
        :rtype: bool
        """
        actual_tested = [tested] if isinstance(tested, str) else tested
        for value in actual_tested:
            ratio = fuzz.ratio(value, reference)
            if ratio >= threshold:
                return True
        return False

    @staticmethod
    def match_simple(tested: list[str], reference: str):
        """A simple strict, case-sensitive string matching between a list of
            candidates and a reference.

        :param tested: list of strings candidate for fuzzy matching
        :type tested: list[str]
        :param reference: the reference against which to try to fuzzy match
        :type reference: str

        :return: whether any of the candidate is a match against the reference
        :rtype: bool
        """
        return Expectation.match_fuzzy(tested, reference, threshold=100)


class DetectionExpectation(Expectation):
    """An expectation that is specific to Detection, i.e. that is used
    by OpenAEV to assert that an inject's execution was detected.
    """

    success_label: str = "Detected"
    failure_label: str = "Not Detected"


class PreventionExpectation(Expectation):
    """An expectation that is specific to Prevention, i.e. that is used
    by OpenAEV to assert that an inject's execution was prevented.
    """

    success_label: str = "Prevented"
    failure_label: str = "Not Prevented"
