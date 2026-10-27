from datetime import datetime

from src.collector.models.source import SourceHandler
from src.collector.protocols.data_fetcher import FetchParamsHook
from src.collector.types.collector import ExpectationsList
from src.collector.utils.expectation_utils import extract_end_date


class DefenderO365SourceHandler(SourceHandler):

    @staticmethod
    def build_fetch_params_hook(batch: ExpectationsList) -> FetchParamsHook | None:
        earliest: datetime | None = None
        for expectation in batch:
            dt: datetime | None = extract_end_date(expectation)
            if dt:
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
