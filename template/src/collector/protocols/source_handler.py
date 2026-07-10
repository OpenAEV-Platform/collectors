from typing import Protocol, runtime_checkable

from pyoaev.apis.inject_expectation.model.expectation import (
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.helpers import OpenAEVDetectionHelper
from pyoaev.signatures.types import SignatureTypes
from src.collector.models.data import OAEVData, TraceData
from src.collector.protocols.data_fetcher import DataFetcherProtocol
from src.collector.protocols.source_data import SourceDataProtocol
from src.collector.types.collector import SignatureGroups, SourceConfig


@runtime_checkable
class SourceHandlerProtocol(Protocol):
    def __init__(self, config: SourceConfig) -> None: ...

    def get_source_data(
        self, data_fetcher: DataFetcherProtocol
    ) -> list[SourceDataProtocol]: ...

    def serialize_as_oaevdata(self, data: SourceDataProtocol) -> OAEVData: ...

    def get_expectation_signature_groups(
        self,
        signatures: list[SignatureTypes],
        expectation: DetectionExpectation | PreventionExpectation,
    ) -> SignatureGroups: ...

    def match_signature_groups_and_oaevdata(
        self,
        signature_groups: SignatureGroups,
        oaev_data: OAEVData,
        oaev_detection_helper: OpenAEVDetectionHelper,
    ) -> bool: ...

    def serialize_as_tracedata(self, data: SourceDataProtocol) -> TraceData: ...

    def match_expectation_and_sourcedata(
        self,
        expectation: DetectionExpectation | PreventionExpectation,
        data: SourceDataProtocol,
    ) -> tuple[bool, bool]: ...
