from typing import Protocol, runtime_checkable

from pyoaev.apis.inject_expectation.model.expectation import (  # type: ignore[import-untyped]
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.helpers import OpenAEVDetectionHelper  # type: ignore[import-untyped]
from pyoaev.signatures.signature_type import (
    SignatureType,  # type: ignore[import-untyped]
)
from src.collector.models.data import OAEVData, TraceData
from src.collector.protocols.data_fetcher import DataFetcherProtocol, FetchParamsHook
from src.collector.protocols.source_data import SourceDataProtocol
from src.collector.types.collector import (
    AlertData,
    ExpectationsList,
    SignatureGroups,
    SourceConfig,
)


@runtime_checkable
class SourceHandlerProtocol(Protocol):
    def __init__(self, config: SourceConfig) -> None: ...

    def build_fetch_params_hook(
        self, batch: ExpectationsList
    ) -> FetchParamsHook | None: ...

    def get_source_data(
        self, data_fetcher: DataFetcherProtocol
    ) -> list[SourceDataProtocol]: ...

    def serialize_as_oaevdata(self, data: SourceDataProtocol) -> OAEVData: ...

    def get_expectation_signature_groups(
        self,
        signatures: list[SignatureType],
        expectation: DetectionExpectation | PreventionExpectation,
    ) -> SignatureGroups: ...

    def get_alert_data_from_oaev_data(
        self,
        signatures: list[SignatureType],
        oaev_data: OAEVData,
    ) -> AlertData: ...

    def match_signature_groups_and_alert_data(
        self,
        signature_groups: SignatureGroups,
        alert_data: AlertData,
        oaev_detection_helper: OpenAEVDetectionHelper,
    ) -> bool: ...

    def serialize_as_tracedata(self, data: SourceDataProtocol) -> TraceData: ...

    def match_expectation_and_sourcedata(
        self,
        expectation: DetectionExpectation | PreventionExpectation,
        data: SourceDataProtocol,
    ) -> tuple[bool, bool]: ...
