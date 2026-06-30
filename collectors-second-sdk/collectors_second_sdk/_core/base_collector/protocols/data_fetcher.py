"""DataFetcher protocol."""

from typing import Protocol, runtime_checkable

from collectors_second_sdk._core.base_collector.protocols.source_data import SourceDataProtocol
from collectors_second_sdk._core.base_collector.types.collector import CustomConfig


@runtime_checkable
class DataFetcherProtocol(Protocol):
    def __init__(self, config: CustomConfig) -> None: ...
    def fetch_data(self) -> list[SourceDataProtocol]: ...
