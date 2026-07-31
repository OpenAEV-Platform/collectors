from typing import Any, Callable, Protocol, TypeAlias, runtime_checkable

from src.collector.protocols.source_data import SourceDataProtocol
from src.collector.types.collector import SourceConfig

FetchParamsHook: TypeAlias = Callable[[dict[str, Any]], dict[str, Any]]


@runtime_checkable
class DataFetcherProtocol(Protocol):
    def __init__(
        self, config: SourceConfig, fetch_params_hook: FetchParamsHook | None = None
    ) -> None: ...

    def fetch_data(self) -> list[SourceDataProtocol]: ...
