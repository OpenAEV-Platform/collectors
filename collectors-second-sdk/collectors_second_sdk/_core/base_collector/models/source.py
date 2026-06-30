"""Source and SourceHandler models."""

from typing import Any

from pydantic import BaseModel
from xtm_oaev_sdk import SignatureTypes

from collectors_second_sdk._core.base_collector.models.data import OAEVData, TraceData
from collectors_second_sdk._core.base_collector.protocols.data_fetcher import DataFetcherProtocol
from collectors_second_sdk._core.base_collector.protocols.source_data import SourceDataProtocol
from collectors_second_sdk._core.base_collector.protocols.source_handler import SourceHandlerProtocol
from collectors_second_sdk._core.base_collector.types.collector import CustomConfig, SignatureGroups


class Source(BaseModel):
    """A source is defined by three elements:
    - the data fetcher model used to fetch the relevant data
    - the source data model used to serialize/deserialize fetched data
    - the list of signature types expected to match the data
    """

    data_fetcher_model: type[DataFetcherProtocol]
    source_data_model: type[SourceDataProtocol]
    signatures: list[SignatureTypes]


class SourceHandler(SourceHandlerProtocol):
    """Interface between the collector engine and the custom source elements."""

    def __init__(self, config: CustomConfig) -> None:
        self.config = config

    def get_source_data(
        self, data_fetcher: DataFetcherProtocol
    ) -> list[SourceDataProtocol]:
        data = data_fetcher.fetch_data()
        return data

    def serialize_as_oaevdata(self, data: SourceDataProtocol) -> OAEVData:
        return data.to_oaev_data()

    def get_expectation_signature_groups(
        self,
        signatures: list[SignatureTypes],
        expectation: any,
    ) -> SignatureGroups:
        supported_types = {sig_type.value for sig_type in signatures}
        signature_groups: SignatureGroups = {}
        for sig in expectation.inject_expectation_signatures:
            if sig.type.value not in supported_types:
                continue
            if sig.type.value == "end_date":
                continue
            signature_groups.setdefault(sig.type.value, []).append(
                {"type": sig.type.value, "value": sig.value}
            )
        return signature_groups

    def match_signature_groups_and_oaevdata(
        self,
        signature_groups: SignatureGroups,
        oaev_data: OAEVData,
        oaev_detection_helper: any,
    ) -> bool:
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
        return data.to_traces_data()

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
