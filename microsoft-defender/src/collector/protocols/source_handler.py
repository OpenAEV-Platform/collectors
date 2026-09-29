from typing import Protocol, runtime_checkable

from pyoaev.apis.inject_expectation.model.expectation import (  # type: ignore[import-untyped]
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.helpers import OpenAEVDetectionHelper  # type: ignore[import-untyped]
from pyoaev.signatures.signature_type import SignatureType
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

    @staticmethod
    def build_fetch_params_hook(batch: ExpectationsList) -> FetchParamsHook | None: ...

    @staticmethod
    def get_source_data(
        data_fetcher: DataFetcherProtocol,
    ) -> list[SourceDataProtocol]: ...

    @staticmethod
    def serialize_as_oaevdata(data: SourceDataProtocol) -> OAEVData: ...

    @staticmethod
    def get_expectation_signature_groups(
        signatures: list[SignatureType],
        expectation: DetectionExpectation | PreventionExpectation,
    ) -> SignatureGroups: ...

    @staticmethod
    def get_alert_data_from_oaev_data(
        signatures: list[SignatureType],
        oaev_data: OAEVData,
    ) -> AlertData: ...

    @staticmethod
    def match_signature_groups_and_alert_data(
        signature_groups: SignatureGroups,
        alert_data: AlertData,
        oaev_detection_helper: OpenAEVDetectionHelper,
    ) -> bool: ...

    @staticmethod
    def serialize_as_tracedata(data: SourceDataProtocol) -> TraceData: ...

    @staticmethod
    def match_expectation_and_sourcedata(
        expectation: DetectionExpectation | PreventionExpectation,
        data: SourceDataProtocol,
    ) -> tuple[bool, bool]: ...
