from datetime import UTC, datetime

from pyoaev.helpers import OpenAEVDetectionHelper
from pyoaev.signatures.types import SignatureTypes
from src.collector.models.source import SourceHandler
from src.collector.protocols.data_fetcher import FetchParamsHook
from src.collector.types.collector import AlertData, ExpectationsList, SignatureGroups


class DefenderSourceHandler(SourceHandler):

    @staticmethod
    def build_fetch_params_hook(batch: ExpectationsList) -> FetchParamsHook | None:
        earliest: datetime | None = None
        for expectation in batch:
            for sig in expectation.inject_expectation_signatures or []:
                if sig.type != SignatureTypes.SIG_TYPE_END_DATE:
                    continue
                try:
                    dt = datetime.fromisoformat(sig.value)

                    if dt.tzinfo:
                        # if there is a timezone, we convert it to UTC
                        dt = dt.astimezone(UTC)
                    else:
                        # we consider, if the END_DATE is naive, that is was produced as UTC
                        dt = dt.replace(tzinfo=UTC)
                except (ValueError, TypeError):
                    continue
                if earliest is None or dt < earliest:
                    earliest = dt

        if earliest is None:
            return None

        def _hook(params: dict) -> dict:
            current = params.get("$filter", "")
            clause = f"createdDateTime ge {earliest.isoformat()}"
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
                intersection = set(signature_values) & set(alert_values)

                if intersection:
                    score += weights.get(key, 1 / 3)

        return score >= 0.99
