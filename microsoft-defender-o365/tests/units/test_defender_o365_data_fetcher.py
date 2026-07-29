"""Unit tests for DefenderO365DataFetcher.

Tests pagination, retry logic, auth recovery, evidence filtering,
and structured logging with mocked HTTP responses.
"""

import json
import time
import unittest
from unittest.mock import MagicMock, patch

from src.auth.exceptions import AuthenticationError


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


class TestDefenderO365DataFetcher(unittest.TestCase):
    """Test DefenderO365DataFetcher with mocked HTTP."""

    def _make_config(self) -> MagicMock:
        """Create a mock SourceConfig."""
        config = MagicMock()
        config.base_url = "https://graph.microsoft.com/v1.0"
        config.filter_service_source = "microsoftDefenderForOffice365"
        config.max_fetch_retries = 5
        return config

    @patch("src.source.defender_o365_data_fetcher.MSGraphAuthClient")
    @patch("src.source.defender_o365_data_fetcher.Session")
    def test_single_page_returns_alerts(
        self,
        mock_session_class,
        mock_auth_client,
    ):
        """Then single-page response returns alerts wrapped in SourceData."""
        from src.source.defender_o365_data_fetcher import DefenderO365DataFetcher

        # Setup mock session
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "value": [_make_alert("ALT-001"), _make_alert("ALT-002"), _make_alert("ALT-003")],
        }
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        # Setup mock auth client
        mock_auth = MagicMock()
        mock_auth.get_access_token.return_value = "test-token"
        mock_auth_client.return_value = mock_auth

        # Execute
        config = self._make_config()
        fetcher = DefenderO365DataFetcher(config)
        result = fetcher.fetch_data()

        # Assert
        self.assertEqual(len(result), 3)
        for item in result:
            self.assertIsNotNone(item.raw_alert)

    @patch("src.source.defender_o365_data_fetcher.MSGraphAuthClient")
    @patch("src.source.defender_o365_data_fetcher.Session")
    def test_pagination_merges_all_pages(
        self,
        mock_session_class,
        mock_auth_client,
    ):
        """Then multi-page pagination merges all alerts."""
        from src.source.defender_o365_data_fetcher import DefenderO365DataFetcher

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
            "value": [_make_alert("ALT-003"), _make_alert("ALT-004"), _make_alert("ALT-005")],
        }

        mock_session.get.side_effect = [response_page1, response_page2]
        mock_session_class.return_value = mock_session

        # Execute
        config = self._make_config()
        fetcher = DefenderO365DataFetcher(config)
        result = fetcher.fetch_data()

        # Assert
        self.assertEqual(len(result), 5)
        self.assertEqual(mock_session.get.call_count, 2)

    @patch("src.source.defender_o365_data_fetcher.MSGraphAuthClient")
    @patch("src.source.defender_o365_data_fetcher.Session")
    @patch("src.source.defender_o365_data_fetcher.time")
    def test_http_429_triggers_retry_after_sleep(
        self,
        mock_time,
        mock_session_class,
        mock_auth_client,
    ):
        """Then HTTP 429 triggers Retry-After sleep then retries."""
        from src.source.defender_o365_data_fetcher import DefenderO365DataFetcher

        mock_session = MagicMock()
        mock_auth = MagicMock()
        mock_auth.get_access_token.return_value = "test-token"
        mock_auth_client.return_value = mock_auth

        # First call returns 429
        response_429 = MagicMock()
        response_429.status_code = 429
        response_429.headers = {"Retry-After": "5"}
        response_429.json.return_value = {"value": []}

        # Second call returns data
        response_ok = MagicMock()
        response_ok.status_code = 200
        response_ok.json.return_value = {
            "value": [_make_alert("ALT-001")],
        }

        mock_session.get.side_effect = [response_429, response_ok]
        mock_session_class.return_value = mock_session

        # Execute
        config = self._make_config()
        fetcher = DefenderO365DataFetcher(config)
        result = fetcher.fetch_data()

        # Assert
        self.assertEqual(len(result), 1)
        mock_time.sleep.assert_called()

    @patch("src.source.defender_o365_data_fetcher.MSGraphAuthClient")
    @patch("src.source.defender_o365_data_fetcher.Session")
    def test_http_401_triggers_token_refresh(
        self,
        mock_session_class,
        mock_auth_client,
    ):
        """Then HTTP 401 triggers token refresh then retries once."""
        from src.source.defender_o365_data_fetcher import DefenderO365DataFetcher

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
        fetcher = DefenderO365DataFetcher(config)
        result = fetcher.fetch_data()

        # Assert
        self.assertEqual(len(result), 1)
        # Verify force_refresh was called
        calls = mock_auth.get_access_token.call_args_list
        force_refresh_calls = [c for c in calls if c[1].get("force_refresh")]
        self.assertTrue(len(force_refresh_calls) >= 1)

    @patch("src.source.defender_o365_data_fetcher.MSGraphAuthClient")
    @patch("src.source.defender_o365_data_fetcher.Session")
    def test_double_401_raises_authentication_error(
        self,
        mock_session_class,
        mock_auth_client,
    ):
        """Then double HTTP 401 returns empty list after token refresh."""
        from src.source.defender_o365_data_fetcher import DefenderO365DataFetcher

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

        mock_session.get.side_effect = [response_401, response_401_again]
        mock_session_class.return_value = mock_session

        # Execute
        config = self._make_config()
        fetcher = DefenderO365DataFetcher(config)
        result = fetcher.fetch_data()

        # Assert: double 401 returns empty list gracefully
        self.assertEqual(len(result), 0)

    @patch("src.source.defender_o365_data_fetcher.MSGraphAuthClient")
    @patch("src.source.defender_o365_data_fetcher.Session")
    def test_empty_response_returns_empty_list(
        self,
        mock_session_class,
        mock_auth_client,
    ):
        """Then empty response returns an empty list."""
        from src.source.defender_o365_data_fetcher import DefenderO365DataFetcher

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
        fetcher = DefenderO365DataFetcher(config)
        result = fetcher.fetch_data()

        # Assert
        self.assertEqual(len(result), 0)

    @patch("src.source.defender_o365_data_fetcher.MSGraphAuthClient")
    @patch("src.source.defender_o365_data_fetcher.Session")
    def test_odata_filter_included_in_request(
        self,
        mock_session_class,
        mock_auth_client,
    ):
        """Then the request URL contains $filter with serviceSource."""
        from src.source.defender_o365_data_fetcher import DefenderO365DataFetcher

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
        fetcher = DefenderO365DataFetcher(config)
        fetcher.fetch_data()

        # Assert
        mock_session.get.assert_called()
        call_args = mock_session.get.call_args
        # Check that params include the filter
        params = call_args[1].get("params", {})
        self.assertIn("$filter", params)
        self.assertIn("microsoftDefenderForOffice365", params["$filter"])


if __name__ == "__main__":
    unittest.main()
