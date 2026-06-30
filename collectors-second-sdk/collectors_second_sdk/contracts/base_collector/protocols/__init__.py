"""Protocol contracts for the base_collector feature."""

from collectors_second_sdk._core.base_collector.protocols.data_fetcher import DataFetcherProtocol
from collectors_second_sdk._core.base_collector.protocols.engine import CollectorEngineProtocol
from collectors_second_sdk._core.base_collector.protocols.source_data import SourceDataProtocol
from collectors_second_sdk._core.base_collector.protocols.source_handler import SourceHandlerProtocol

__all__ = [
    "CollectorEngineProtocol",
    "DataFetcherProtocol",
    "SourceDataProtocol",
    "SourceHandlerProtocol",
]
