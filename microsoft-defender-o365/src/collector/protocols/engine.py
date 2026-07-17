from typing import Protocol, runtime_checkable

from pyoaev.client import OpenAEV

from src.collector.models.source import Source
from src.collector.protocols.source_handler import SourceHandlerProtocol
from src.collector.types.collector import SourceConfig


@runtime_checkable
class CollectorEngineProtocol(Protocol):
    def __init__(
        self,
        name: str,
        collector_id: str,
        source: Source,
        source_handler: SourceHandlerProtocol,
        oaev_api: OpenAEV,
        batching: bool = False,
    ) -> None: ...

    def configure_engine(
        self, config: SourceConfig, batching: bool = False
    ) -> None: ...

    def run_engine(self) -> None: ...
