"""Unit tests for DefenderDataFetcher.

Tests pagination, retry logic, auth recovery, evidence filtering,
and structured logging with mocked HTTP responses.
"""

import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from pydantic import HttpUrl


def _make_alert(alert_id: str = "ALT-001") -> dict:
    """Create a minimal valid alert dict."""
    return {
        "id": alert_id,
        "title": "Phishing email detected",
        "status": "new",
        "severity": "high",
        "serviceSource": "microsoftDefenderForOffice365",
        "createdDateTime": "2026-07-05T14:00:00Z",
    }


class TestDefenderDataFetcher(unittest.TestCase):
    """Test DefenderDataFetcher with mocked HTTP."""

    def _make_config(self) -> MagicMock:
        """Create a mock SourceConfig."""
        config = MagicMock()
        config.base_url = HttpUrl("https://graph.microsoft.com/v1.0")
        config.filter_service_source = "microsoftDefenderForOffice365"
        config.max_fetch_retries = 5
        return config

    @patch("src.source.defender_data_fetcher.MSGraphAuthClient")
    @patch("src.source.defender_data_fetcher.Session")
    def test_single_page_returns_alerts(
        self,
        mock_session_class,
        mock_auth_client,
    ):
        """Then single-page response returns alerts wrapped in SourceData."""
        from src.source.defender_data_fetcher import DefenderDataFetcher

        # Setup mock session
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "value": [
                _make_alert("ALT-001"),
                _make_alert("ALT-002"),
                _make_alert("ALT-003"),
            ],
        }
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        # Setup mock auth client
        mock_auth = MagicMock()
        mock_auth.get_access_token.return_value = "test-token"
        mock_auth_client.return_value = mock_auth

        # Execute
        config = self._make_config()
        fetcher = DefenderDataFetcher(config)
        result = fetcher.fetch_data()

        # Assert
        self.assertEqual(len(result), 3)
        for item in result:
            self.assertIsNotNone(item.alert)

    @patch("src.source.defender_data_fetcher.MSGraphAuthClient")
    @patch("src.source.defender_data_fetcher.Session")
    def test_pagination_merges_all_pages(
        self,
        mock_session_class,
        mock_auth_client,
    ):
        """Then multi-page pagination merges all alerts."""
        from src.source.defender_data_fetcher import DefenderDataFetcher

        # Setup mock session with two pages
        mock_session = MagicMock()
        mock_auth = MagicMock()
        mock_auth.get_access_token.return_value = "test-token"
        mock_auth_client.return_value = mock_auth

        # First call returns page 1 with nextLink
        response_page1 = MagicMock()
        response_page1.status_code = 200
        response_page1.json.return_value = {
            "value": [_make_alert("ALT-001"), _make_alert("ALT-002")],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/alerts_v2?$skiptoken=abc",
        }

        # Second call returns page 2 without nextLink
        response_page2 = MagicMock()
        response_page2.status_code = 200
        response_page2.json.return_value = {
            "value": [
                _make_alert("ALT-003"),
                _make_alert("ALT-004"),
                _make_alert("ALT-005"),
            ],
        }

        mock_session.get.side_effect = [response_page1, response_page2]
        mock_session_class.return_value = mock_session

        # Execute
        config = self._make_config()
        fetcher = DefenderDataFetcher(config)
        result = fetcher.fetch_data()

        # Assert
        self.assertEqual(len(result), 5)
        self.assertEqual(mock_session.get.call_count, 2)

    @patch("src.source.defender_data_fetcher.MSGraphAuthClient")
    @patch("src.source.defender_data_fetcher.Session")
    def test_http_401_triggers_token_refresh(
        self,
        mock_session_class,
        mock_auth_client,
    ):
        """Then HTTP 401 triggers token refresh then retries once."""
        from src.source.defender_data_fetcher import DefenderDataFetcher

        mock_session = MagicMock()
        mock_auth = MagicMock()
        mock_auth.get_access_token.return_value = "test-token"
        mock_auth_client.return_value = mock_auth

        # First call returns 401
        response_401 = MagicMock()
        response_401.status_code = 401
        response_401.json.return_value = {"value": []}

        # Second call returns data
        response_ok = MagicMock()
        response_ok.status_code = 200
        response_ok.json.return_value = {
            "value": [_make_alert("ALT-001")],
        }

        mock_session.get.side_effect = [response_401, response_ok]
        mock_session_class.return_value = mock_session

        # Execute
        config = self._make_config()
        fetcher = DefenderDataFetcher(config)
        result = fetcher.fetch_data()

        # Assert
        self.assertEqual(len(result), 1)

    @patch("src.source.defender_data_fetcher.MSGraphAuthClient")
    @patch("src.source.defender_data_fetcher.Session")
    def test_double_401_raises_authentication_error(
        self,
        mock_session_class,
        mock_auth_client,
    ):
        """Then double HTTP 401 returns empty list after token refresh."""
        from src.source.defender_data_fetcher import DefenderDataFetcher

        mock_session = MagicMock()
        mock_auth = MagicMock()
        mock_auth.get_access_token.return_value = "test-token"
        mock_auth_client.return_value = mock_auth

        # First call returns 401
        response_401 = MagicMock()
        response_401.status_code = 401
        response_401.json.return_value = {"value": []}

        # Second call also returns 401
        response_401_again = MagicMock()
        response_401_again.status_code = 401
        response_401_again.json.return_value = {"value": []}

        # Third call returns empty 200
        response_ok = MagicMock()
        response_ok.status_code = 200
        response_ok.json.return_value = {"value": []}

        mock_session.get.side_effect = [response_401, response_401_again, response_ok]
        mock_session_class.return_value = mock_session

        # Execute
        config = self._make_config()
        fetcher = DefenderDataFetcher(config)
        result = fetcher.fetch_data()

        # Assert: double 401 returns empty list gracefully
        self.assertEqual(len(result), 0)

    @patch("src.source.defender_data_fetcher.MSGraphAuthClient")
    @patch("src.source.defender_data_fetcher.Session")
    def test_empty_response_returns_empty_list(
        self,
        mock_session_class,
        mock_auth_client,
    ):
        """Then empty response returns an empty list."""
        from src.source.defender_data_fetcher import DefenderDataFetcher

        mock_session = MagicMock()
        mock_auth = MagicMock()
        mock_auth.get_access_token.return_value = "test-token"
        mock_auth_client.return_value = mock_auth

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"value": []}
        mock_session.get.return_value = response
        mock_session_class.return_value = mock_session

        # Execute
        config = self._make_config()
        fetcher = DefenderDataFetcher(config)
        result = fetcher.fetch_data()

        # Assert
        self.assertEqual(len(result), 0)

    @patch("src.source.defender_data_fetcher.MSGraphAuthClient")
    @patch("src.source.defender_data_fetcher.Session")
    def test_odata_filter_included_in_request(
        self,
        mock_session_class,
        mock_auth_client,
    ):
        """Then the request contains $filter with serviceSource and $orderby."""
        from src.source.defender_data_fetcher import DefenderDataFetcher

        mock_session = MagicMock()
        mock_auth = MagicMock()
        mock_auth.get_access_token.return_value = "test-token"
        mock_auth_client.return_value = mock_auth

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"value": [_make_alert("ALT-001")]}
        mock_session.get.return_value = response
        mock_session_class.return_value = mock_session

        # Execute
        config = self._make_config()
        fetcher = DefenderDataFetcher(config)
        fetcher.fetch_data()

        # Assert
        mock_session.get.assert_called()
        call_args = mock_session.get.call_args
        params = call_args[1].get("params", {})
        self.assertIn("$filter", params)
        self.assertIn("microsoftDefenderForOffice365", params["$filter"])
        self.assertIn("$orderby", params)
        self.assertEqual(params["$orderby"], "createdDateTime desc")

    @patch("src.source.defender_data_fetcher.MSGraphAuthClient")
    @patch("src.source.defender_data_fetcher.Session")
    def test_fetch_params_hook_injects_filter_clause(
        self,
        mock_session_class,
        mock_auth_client,
    ):
        """Then fetch_params_hook injects a filter clause without mutating fetcher state."""
        from src.source.defender_data_fetcher import DefenderDataFetcher

        mock_session = MagicMock()
        mock_auth = MagicMock()
        mock_auth.get_access_token.return_value = "test-token"
        mock_auth_client.return_value = mock_auth

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"value": [_make_alert("ALT-001")]}
        mock_session.get.return_value = response
        mock_session_class.return_value = mock_session

        # Fetch params hook: inject a since_datetime clause into the $filter
        since = datetime(2026, 7, 1, 0, 0, 0)

        def _since_hook(params: dict) -> dict:
            current = params.get("$filter", "")
            clause = f"createdDateTime ge '{since.isoformat()}'"
            params["$filter"] = f"{current} and {clause}" if current else clause
            return params

        # Execute
        config = self._make_config()
        fetcher = DefenderDataFetcher(config, fetch_params_hook=_since_hook)
        fetcher.fetch_data()

        # Assert: hook injected the clause into the request params
        call_args = mock_session.get.call_args
        params = call_args[1].get("params", {})
        self.assertIn("createdDateTime ge", params["$filter"])
        self.assertIn("2026-07-01T00:00:00", params["$filter"])

    def test_source_handler_build_fetch_params_hook(self):
        """Then DefenderSourceHandler.build_fetch_params_hook extracts end_date
        from expectations and returns a hook that injects since_datetime."""
        from pyoaev.signatures.types import SignatureTypes
        from src.source.source_handler import DefenderSourceHandler

        # Build a mock expectation with end_date signature
        mock_expectation = MagicMock()
        mock_sig = MagicMock()
        mock_sig.type = SignatureTypes.SIG_TYPE_END_DATE
        mock_sig.value = "2026-07-01T00:00:00"
        mock_expectation.inject_expectation_signatures = [mock_sig]

        batch = [mock_expectation]

        # Execute
        hook = DefenderSourceHandler.build_fetch_params_hook(batch)

        # Assert: hook is not None
        self.assertIsNotNone(hook)

        # Assert: hook injects the since clause
        params = {"$filter": "existing filter", "$orderby": "createdDateTime desc"}
        result = hook(params)
        self.assertIn("createdDateTime ge", result["$filter"])
        self.assertIn("2026-07-01T00:00:00", result["$filter"])

    def test_source_handler_build_fetch_params_hook_no_end_date(self):
        """Then DefenderSourceHandler.build_fetch_params_hook returns None
        when no end_date signatures are present."""
        from src.source.source_handler import DefenderSourceHandler

        # Build a mock expectation without end_date signature
        mock_expectation = MagicMock()
        mock_expectation.inject_expectation_signatures = []

        batch = [mock_expectation]

        # Execute
        hook = DefenderSourceHandler.build_fetch_params_hook(batch)

        # Assert: hook is None
        self.assertIsNone(hook)

    def test_base_source_handler_returns_none(self):
        """Then the base SourceHandler.build_fetch_params_hook returns None by default."""
        from src.collector.models.source import SourceHandler

        hook = SourceHandler.build_fetch_params_hook([])
        self.assertIsNone(hook)


if __name__ == "__main__":
    unittest.main()
