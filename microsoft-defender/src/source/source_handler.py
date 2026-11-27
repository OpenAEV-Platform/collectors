from datetime import datetime

from pyoaev.apis.inject_expectation.model.expectation import (  # type: ignore[import-untyped]
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.helpers import OpenAEVDetectionHelper
from pyoaev.signatures.types import SignatureTypes
from src.collector.models.source import SourceHandler
from src.collector.protocols.data_fetcher import FetchParamsHook
from src.collector.protocols.source_data import SourceDataProtocol
from src.collector.types.collector import AlertData, ExpectationsList, SignatureGroups
from src.collector.utils.expectation_utils import extract_date_with_fallback
from src.source.signatures import SUPPORTED_SIGNATURES


class DefenderSourceHandler(SourceHandler):

    @staticmethod
    def build_fetch_params_hook(batch: ExpectationsList) -> FetchParamsHook | None:
        earliest: datetime | None = None
        for expectation in batch:
            dt: datetime | None = extract_date_with_fallback(expectation)
            if dt:
                if earliest is None or dt < earliest:
                    earliest = dt

        if earliest is None:
            return None

        def _hook(params: dict) -> dict:
            current = params.get("$filter", "")
            clause = f"lastUpdateDateTime ge {earliest.isoformat()}"
            params["$filter"] = f"{current} and {clause}" if current else clause
            return params

        return _hook

    @staticmethod
    def match_signature_groups_and_alert_data(
        signature_groups: SignatureGroups,
        alert_data: AlertData,
        oaev_detection_helper: OpenAEVDetectionHelper,
    ) -> bool:
        """
        Weighted matching system:
        - look for any match per signature type (between multiple values on both side)
        - update a global score according to the weight given to a signature type
        Default weight is 1/3, threshold for matching is 1,
        the size of the intersection does not influence the scoring
        (a.k.a. two match on SIG_TYPE_TARGET_IPV4_ADDRESS is the same value as a single match)
        """
        relax_matching_keys = [
            SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
            SignatureTypes.SIG_TYPE_PROCESS_NAME,
        ]

        weights = {
            SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME: 1,
            SignatureTypes.SIG_TYPE_PROCESS_NAME: 2 / 3,
            SignatureTypes.SIG_TYPE_COMMAND_LINE: 2 / 3,
            SignatureTypes.SIG_TYPE_FILE_NAME: 2 / 3,
        }

        score = 0

        for key in signature_groups:
            if key in alert_data:
                signature_values = [
                    sig.get("value")
                    for sig in signature_groups[key]
                    if sig.get("value")
                ]
                alert_values = alert_data[key].get("data", [])

                # case where a "a in b" is allowed for this signature types
                if key in relax_matching_keys:
                    intersection = False
                    for alert_value in alert_values:
                        for signature_value in signature_values:
                            if str(signature_value).lower() in str(alert_value).lower():
                                intersection = True
                                break
                        # if the match has been found for current signature_value,
                        # get out of the alert_value loop too
                        if intersection:
                            break
                # case where a "a == b" is required for this signature types
                else:
                    intersection = set(signature_values) & set(alert_values)

                if intersection:
                    score += weights.get(key, 1 / 3)

        return score >= 0.99

    @classmethod
    def match_expectation_and_sourcedata(
        cls,
        expectation: DetectionExpectation | PreventionExpectation,
        data: SourceDataProtocol,
    ) -> tuple[bool, bool]:
        """Detection: any matched alert. Prevention: the alert is handled
        (inProgress, resolved), or one evidence Defender blocked or prevented
        matches the expectation by itself (collectors#675): a blocked process
        unrelated to the expected implant never validates the prevention.
        """
        matchflag, breakflag = super().match_expectation_and_sourcedata(
            expectation, data
        )
        if matchflag or not isinstance(expectation, PreventionExpectation):
            return matchflag, breakflag

        prevented_evidences = getattr(data, "prevented_evidences_oaev_data", None)
        if prevented_evidences is None:
            return matchflag, breakflag

        signature_groups = cls.get_expectation_signature_groups(
            SUPPORTED_SIGNATURES, expectation
        )
        for oaev_data in prevented_evidences():
            alert_data = cls.get_alert_data_from_oaev_data(
                SUPPORTED_SIGNATURES, oaev_data
            )
            # the weighted matcher above does not use the detection helper
            if cls.match_signature_groups_and_alert_data(
                signature_groups, alert_data, None
            ):
                return True, True
        return matchflag, breakflag
