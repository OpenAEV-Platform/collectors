"""Expectation adapters: expectations fetched from the platform, matched
against alerts and updated through the injected API client.

Each adapter speaks the expectations seam types and delegates to the core
implementation of its ports.
"""

from collectors_sdk._core.expectations import ExpectationMatcher, ExpectationUpdates
from collectors_sdk.seam.expectations import (
    ExpectationData,
    ExpectationMatchingPort,
    ExpectationSignature,
    ExpectationTypeEnum,
    ExpectationUpdatePort,
)
from xtm_oaev_sdk import SignatureType

__all__ = [
    "DetectionExpectation",
    "Expectation",
    "ExpectationSignature",
    "ExpectationTypeEnum",
    "PreventionExpectation",
]

_matching: ExpectationMatchingPort = ExpectationMatcher()
_updates: ExpectationUpdatePort = ExpectationUpdates()


class Expectation(ExpectationData):
    """An expectation represents an expected outcome of a BAS run.
    For example, in the case of running an attack command line, the
    expectation may be that security software has _detected_ it, while
    another expectation may be that the attack was _prevented_.
    """

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
            inject_expectation=_updates.outcome(
                success, sender_id, metadata, self.success_label, self.failure_label
            ),
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
        return _matching.match_alert(
            self.inject_expectation_signatures,
            relevant_signature_types,
            alert_data,
            self.match_fuzzy,
            self.match_simple,
        )

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
        return _matching.match_fuzzy(tested, reference, threshold)

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
