"""Contract compliance: DataFetcherProtocol output contract validation.

Ensures DefenderO365DataFetcher satisfies the template DataFetcherProtocol
regardless of internal implementation changes. Prevents protocol drift.
"""

import pytest
from src.collector.protocols.data_fetcher import DataFetcherProtocol
from src.source.data_fetcher import MicrosoftDefenderO365DataFetcher


class TestDataFetcherContractCompliance:
    """Verify DefenderO365DataFetcher adheres to DataFetcherProtocol."""

    def test_data_fetcher_satisfies_protocol(
        self, source_config_fixture: object
    ) -> None:
        """Then DefenderO365DataFetcher satisfies DataFetcherProtocol."""
        fetcher = MicrosoftDefenderO365DataFetcher(source_config_fixture)
        assert isinstance(fetcher, DataFetcherProtocol)

    def test_fetch_data_returns_list(
        self, source_config_fixture: object
    ) -> None:
        """Then fetch_data() returns a list."""
        fetcher = MicrosoftDefenderO365DataFetcher(source_config_fixture)
        result = fetcher.fetch_data()
        assert isinstance(result, list)

    def test_fetch_data_items_satisfy_source_data_protocol(
        self, source_config_fixture: object
    ) -> None:
        """Then each item in fetch_data() result satisfies SourceDataProtocol."""
        from src.collector.protocols.source_data import SourceDataProtocol

        fetcher = MicrosoftDefenderO365DataFetcher(source_config_fixture)
        result = fetcher.fetch_data()
        for item in result:
            assert isinstance(item, SourceDataProtocol)

    def test_fetch_data_items_have_required_source_data_methods(
        self, source_config_fixture: object
    ) -> None:
        """Then each item has all SourceDataProtocol methods."""
        fetcher = MicrosoftDefenderO365DataFetcher(source_config_fixture)
        result = fetcher.fetch_data()
        required_methods = [
            "to_oaev_data",
            "to_traces_data",
            "is_prevented",
            "is_detected",
            "__str__",
        ]
        for item in result:
            for method_name in required_methods:
                assert hasattr(item, method_name), (
                    f"Missing required method: {method_name}"
                )
                method = getattr(item, method_name)
                assert callable(method), (
                    f"Method {method_name} is not callable"
                )
