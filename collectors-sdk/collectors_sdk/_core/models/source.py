"""Source and SourceHandler models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from collectors_sdk._core.models.data import OAEVData, TraceData
from collectors_sdk._core.protocols import (
    DataFetcherProtocol,
    SourceDataProtocol,
)

__all__ = ["Source", "SourceHandler"]


class Source(BaseModel):
    """A source is defined by its data fetcher, source data model, and signatures.

    The data_fetcher_model and source_data_model are type references (classes),
    not instances — requires arbitrary_types_allowed.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    data_fetcher_model: type[DataFetcherProtocol]
    source_data_model: type[SourceDataProtocol]
    signatures: list[Any]


class SourceHandler:
    """Default implementation of SourceHandlerProtocol.

    Provides the bridge between the engine and custom source elements.
    """

    def __init__(self, config: Any) -> None:
        self.config = config

    def get_source_data(
        self, data_fetcher: DataFetcherProtocol
    ) -> list[Any]:
        """Fetch source data using the provided data fetcher."""
        return data_fetcher.fetch_data()

    def serialize_as_oaevdata(self, data: SourceDataProtocol) -> OAEVData:
        """Serialize source data as OAEVData."""
        result: OAEVData = data.to_oaev_data()
        return result

    def get_expectation_signature_groups(
        self,
        signatures: list[Any],
        expectation: Any,
    ) -> dict[str, list[dict[str, str]]]:
        """Group expectation signatures by type, filtered against source signatures."""
        supported_types = {
            sig_type.value if hasattr(sig_type, "value") else str(sig_type)
            for sig_type in signatures
        }
        signature_groups: dict[str, list[dict[str, str]]] = {}
        for sig in getattr(expectation, "inject_expectation_signatures", []):
            sig_type_value = sig.type.value if hasattr(sig.type, "value") else str(sig.type)
            if sig_type_value not in supported_types:
                continue
            if sig_type_value == "end_date":
                continue
            signature_groups.setdefault(sig_type_value, []).append(
                {"type": sig_type_value, "value": sig.value}
            )
        return signature_groups

    def match_signature_groups_and_oaevdata(
        self,
        signature_groups: dict[str, list[dict[str, str]]],
        oaev_data: Any,
        oaev_detection_helper: Any,
    ) -> bool:
        """Match signature groups against OAEVData using the detection helper."""
        if not oaev_data:
            return False
        for sig_type, signature_data in signature_groups.items():
            try:
                filtered_data = {sig_type: getattr(oaev_data, sig_type)}
            except AttributeError:
                return False
            match_result = oaev_detection_helper.match_alert_elements(
                signature_data, filtered_data
            )
            if not match_result:
                return False
        return True

    def serialize_as_tracedata(self, data: SourceDataProtocol) -> TraceData:
        """Serialize source data as TraceData."""
        result: TraceData = data.to_traces_data()
        return result

    def match_expectation_and_sourcedata(
        self,
        expectation: Any,
        data: SourceDataProtocol,
    ) -> tuple[bool, bool]:
        """Match expectation with source data to determine satisfaction.

        Returns (matchflag, breakflag) — breakflag is True for prevention
        matches to skip further processing.
        """
        matchflag = False
        breakflag = False

        # Check if this is a prevention expectation by class name
        cls_name = type(expectation).__name__
        if cls_name == "PreventionExpectation":
            if data.is_prevented():
                matchflag = True
                breakflag = True
        else:
            if data.is_detected():
                matchflag = True
        return matchflag, breakflag
