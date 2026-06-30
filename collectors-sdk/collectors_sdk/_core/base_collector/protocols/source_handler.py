"""SourceHandler protocol."""

from typing import Protocol, runtime_checkable

from xtm_oaev_sdk import SignatureTypes

from collectors_sdk._core.base_collector.models.data import OAEVData, TraceData
from collectors_sdk._core.base_collector.protocols.data_fetcher import DataFetcherProtocol
from collectors_sdk._core.base_collector.protocols.source_data import SourceDataProtocol
from collectors_sdk._core.base_collector.types.collector import CustomConfig, SignatureGroups


@runtime_checkable
class SourceHandlerProtocol(Protocol):
    def __init__(self, config: CustomConfig) -> None: ...

    def get_source_data(
        self, data_fetcher: DataFetcherProtocol
    ) -> list[SourceDataProtocol]: ...

    def serialize_as_oaevdata(self, data: SourceDataProtocol) -> OAEVData: ...

    def get_expectation_signature_groups(
        self,
        signatures: list[SignatureTypes],
        expectation: any,
    ) -> SignatureGroups: ...

    def match_signature_groups_and_oaevdata(
        self,
        signature_groups: SignatureGroups,
        oaev_data: OAEVData,
        oaev_detection_helper: any,
    ) -> bool: ...

    def serialize_as_tracedata(self, data: SourceDataProtocol) -> TraceData: ...

    def match_expectation_and_sourcedata(
        self,
        expectation: any,
        data: SourceDataProtocol,
    ) -> tuple[bool, bool]: ...
