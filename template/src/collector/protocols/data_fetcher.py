from typing import Protocol, runtime_checkable

from src.collector.protocols.source_data import SourceDataProtocol


@runtime_checkable
class DataFetcherProtocol(Protocol):
    def fetch_data(self) -> list[SourceDataProtocol]: ...
