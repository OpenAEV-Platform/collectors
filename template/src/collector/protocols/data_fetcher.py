from typing import Protocol, runtime_checkable

from src.collector.protocols.source_data import SourceDataProtocol
from src.collector.types.collector import SourceConfig


@runtime_checkable
class DataFetcherProtocol(Protocol):
    def __init__(self, config: SourceConfig) -> None: ...

    def fetch_data(self) -> list[SourceDataProtocol]: ...
