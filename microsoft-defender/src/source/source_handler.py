from datetime import UTC, datetime

from pyoaev.signatures.types import SignatureTypes
from src.collector.models.source import SourceHandler
from src.collector.protocols.data_fetcher import FetchParamsHook
from src.collector.types.collector import ExpectationsList


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

                    if not dt.tzinfo:
                        dt = dt.astimezone(UTC)
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
