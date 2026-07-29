"""Contract compliance: DataFetcherProtocol output contract validation.

Ensures DefenderO365DataFetcher satisfies the template DataFetcherProtocol
regardless of internal implementation changes. Prevents protocol drift.
"""

from unittest.mock import MagicMock, patch

import pytest
from src.collector.protocols.data_fetcher import DataFetcherProtocol
from src.source.data_fetcher import MicrosoftDefenderO365DataFetcher


def _mock_fetcher(source_config_fixture: object) -> tuple:
    """Build a mocked DefenderO365DataFetcher with mocked auth and session.

    Returns:
        A (fetcher, mock_session, mock_auth) tuple.
    """
    mock_session = MagicMock()
    mock_auth = MagicMock()
    mock_auth.get_access_token.return_value = "test-token"

    # Return a single-page response with one alert
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "value": [
            {
                "id": "ALT-001",
                "title": "Test alert",
                "status": "new",
                "severity": "high",
                "serviceSource": "microsoftDefenderForOffice365",
                "createdDateTime": "2026-07-05T14:00:00Z",
            }
        ]
    }
    mock_session.get.return_value = mock_response

    with (
        patch(
            "src.source.defender_o365_data_fetcher.MSGraphAuthClient",
            return_value=mock_auth,
        ),
        patch("src.source.defender_o365_data_fetcher.Session", return_value=mock_session),
    ):
        fetcher = MicrosoftDefenderO365DataFetcher(source_config_fixture)
        return fetcher, mock_session, mock_auth


class TestDataFetcherContractCompliance:
    """Verify DefenderO365DataFetcher adheres to DataFetcherProtocol."""

    def test_data_fetcher_satisfies_protocol(
        self, source_config_fixture: object
    ) -> None:
        """Then DefenderO365DataFetcher satisfies DataFetcherProtocol."""
        fetcher, _, _ = _mock_fetcher(source_config_fixture)
        assert isinstance(fetcher, DataFetcherProtocol)

    def test_fetch_data_returns_list(
        self, source_config_fixture: object
    ) -> None:
        """Then fetch_data() returns a list."""
        fetcher, _, _ = _mock_fetcher(source_config_fixture)
        result = fetcher.fetch_data()
        assert isinstance(result, list)

    def test_fetch_data_items_satisfy_source_data_protocol(
        self, source_config_fixture: object
    ) -> None:
        """Then each item in fetch_data() result satisfies SourceDataProtocol."""
        from src.collector.protocols.source_data import SourceDataProtocol

        fetcher, _, _ = _mock_fetcher(source_config_fixture)
        result = fetcher.fetch_data()
        for item in result:
            assert isinstance(item, SourceDataProtocol)

    def test_fetch_data_items_have_required_source_data_methods(
        self, source_config_fixture: object
    ) -> None:
        """Then each item has all SourceDataProtocol methods."""
        fetcher, _, _ = _mock_fetcher(source_config_fixture)
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
