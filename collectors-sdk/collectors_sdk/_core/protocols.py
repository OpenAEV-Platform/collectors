"""Behavioral Protocol interfaces for the collectors SDK.

All Protocols use @runtime_checkable for isinstance() checks.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

__all__ = [
    "CollectorEngineProtocol",
    "DataFetcherProtocol",
    "SourceDataProtocol",
    "SourceHandlerProtocol",
]


@runtime_checkable
class SourceDataProtocol(Protocol):
    """Contract for source data objects that can be serialized to OAEV formats."""

    def to_oaev_data(self) -> Any: ...

    def to_traces_data(self) -> Any: ...

    def is_prevented(self) -> bool: ...

    def is_detected(self) -> bool: ...

    def __str__(self) -> str: ...


@runtime_checkable
class DataFetcherProtocol(Protocol):
    """Contract for data fetchers that retrieve source data."""

    def fetch_data(self) -> list[Any]: ...


@runtime_checkable
class SourceHandlerProtocol(Protocol):
    """Contract for source handlers that bridge fetched data and the engine."""

    def get_source_data(self, data_fetcher: DataFetcherProtocol) -> list[Any]: ...

    def serialize_as_oaevdata(self, data: SourceDataProtocol) -> Any: ...

    def get_expectation_signature_groups(
        self, signatures: list[Any], expectation: Any
    ) -> dict[str, list[dict[str, str]]]: ...

    def match_signature_groups_and_oaevdata(
        self,
        signature_groups: dict[str, list[dict[str, str]]],
        oaev_data: Any,
        oaev_detection_helper: Any,
    ) -> bool: ...

    def serialize_as_tracedata(self, data: SourceDataProtocol) -> Any: ...

    def match_expectation_and_sourcedata(
        self, expectation: Any, data: SourceDataProtocol
    ) -> tuple[bool, bool]: ...


@runtime_checkable
class CollectorEngineProtocol(Protocol):
    """Contract for collector engines that process expectations."""

    def configure_engine(self, config: Any, batching: bool = False) -> None: ...

    def run_engine(self) -> None: ...
