"""RED tests for the 4 behavioral Protocols."""

from __future__ import annotations

from typing import Any

from collectors_second_sdk import (
    CollectorEngineProtocol,
    DataFetcherProtocol,
    SourceDataProtocol,
    SourceHandlerProtocol,
)


class TestCollectorEngineProtocol:
    """CollectorEngineProtocol behavioral contract."""

    def test_is_runtime_checkable(self) -> None:
        class Good:
            def configure_engine(self, config: Any, batching: bool = False) -> None: ...
            def run_engine(self) -> None: ...

        assert isinstance(Good(), CollectorEngineProtocol)

    def test_negative_missing_method(self) -> None:
        class Bad:
            pass

        assert not isinstance(Bad(), CollectorEngineProtocol)


class TestDataFetcherProtocol:
    """DataFetcherProtocol behavioral contract."""

    def test_is_runtime_checkable(self) -> None:
        class Good:
            def fetch_data(self) -> list[Any]:
                return []

        assert isinstance(Good(), DataFetcherProtocol)

    def test_negative_missing_method(self) -> None:
        class Bad:
            pass

        assert not isinstance(Bad(), DataFetcherProtocol)


class TestSourceDataProtocol:
    """SourceDataProtocol behavioral contract."""

    def test_is_runtime_checkable(self) -> None:
        class Good:
            def to_oaev_data(self) -> Any: ...
            def to_traces_data(self) -> Any: ...
            def is_prevented(self) -> bool:
                return False
            def is_detected(self) -> bool:
                return True
            def __str__(self) -> str:
                return "good"

        assert isinstance(Good(), SourceDataProtocol)

    def test_negative_missing_method(self) -> None:
        class Bad:
            def to_oaev_data(self) -> Any: ...

        assert not isinstance(Bad(), SourceDataProtocol)


class TestSourceHandlerProtocol:
    """SourceHandlerProtocol behavioral contract."""

    def test_is_runtime_checkable(self) -> None:
        class Good:
            def get_source_data(self, data_fetcher: Any) -> list[Any]:
                return []
            def serialize_as_oaevdata(self, data: Any) -> Any: ...
            def get_expectation_signature_groups(
                self, signatures: Any, expectation: Any
            ) -> Any: ...
            def match_signature_groups_and_oaevdata(
                self, sig_groups: Any, oaev_data: Any, helper: Any
            ) -> bool:
                return False
            def serialize_as_tracedata(self, data: Any) -> Any: ...
            def match_expectation_and_sourcedata(
                self, expectation: Any, data: Any
            ) -> tuple[bool, bool]:
                return (False, False)

        assert isinstance(Good(), SourceHandlerProtocol)

    def test_negative_missing_method(self) -> None:
        class Bad:
            pass

        assert not isinstance(Bad(), SourceHandlerProtocol)
