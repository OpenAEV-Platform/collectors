"""CollectorEngine protocol."""

from typing import Protocol, runtime_checkable

from collectors_sdk._core.base_collector.models.source import Source
from collectors_sdk._core.base_collector.protocols.source_handler import SourceHandlerProtocol
from collectors_sdk._core.base_collector.types.collector import CustomConfig


@runtime_checkable
class CollectorEngineProtocol(Protocol):
    def __init__(
        self,
        name: str,
        collector_id: str,
        source: Source,
        source_handler: SourceHandlerProtocol,
        oaev_api: any,
        batching: bool = False,
    ) -> None: ...

    def configure_engine(
        self, config: CustomConfig, batching: bool = False
    ) -> None: ...

    def run_engine(self) -> None: ...
