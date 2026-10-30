"""Unit tests for DefenderO365DataFetcher.

Tests pagination, retry logic, auth recovery, evidence filtering,
and structured logging with mocked HTTP responses.
"""

import unittest
from unittest.mock import MagicMock

import src.source.source_handler as module
from pyoaev.signatures.types import SignatureTypes


class TestDefenderO365SourceHandler(unittest.TestCase):
    """Test DefenderO365SourceHandler."""

    def test_base_source_handler_returns_none(self):
        """Then the base SourceHandler.build_fetch_params_hook returns None by default."""
        from src.collector.models.source import SourceHandler

        hook = SourceHandler.build_fetch_params_hook([])
        self.assertIsNone(hook)

    def test_source_handler_build_fetch_params_hook(self):
        """Then DefenderO365SourceHandler.build_fetch_params_hook extracts end_date
        from expectations and returns a hook that injects since_datetime."""
        # Build a mock expectation with end_date signature
        mock_expectation = MagicMock()
        mock_sig = MagicMock()
        mock_sig.type = SignatureTypes.SIG_TYPE_END_DATE
        mock_sig.value = "2026-07-01T00:00:00"
        mock_expectation.inject_expectation_signatures = [mock_sig]

        batch = [mock_expectation]

        # Execute
        hook = module.DefenderO365SourceHandler.build_fetch_params_hook(batch)

        # Assert: hook is not None
        self.assertIsNotNone(hook)

        # Assert: hook injects the since clause
        params = {"$filter": "existing filter", "$orderby": "createdDateTime desc"}
        result = hook(params)
        self.assertIn("createdDateTime ge", result["$filter"])
        self.assertIn("2026-07-01T00:00:00", result["$filter"])

    def test_source_handler_build_fetch_params_hook_both(self):
        """Then DefenderO365SourceHandler.build_fetch_params_hook extracts end_date
        from expectations and returns a hook that injects since_datetime."""
        # Build a mock expectation with end_date signature
        mock_expectation = MagicMock()
        mock_sig = MagicMock()
        mock_sig.type = SignatureTypes.SIG_TYPE_END_DATE
        mock_sig.value = "2026-07-04T00:00:00"
        mock_expectation.inject_expectation_signatures = [mock_sig]

        mock_expectation2 = MagicMock()
        mock_sig2 = MagicMock()
        mock_sig2.type = SignatureTypes.SIG_TYPE_END_DATE
        mock_sig2.value = "2026-07-01T00:00:00"
        mock_expectation2.inject_expectation_signatures = [mock_sig2]

        batch = [mock_expectation, mock_expectation2]

        # Execute
        hook = module.DefenderO365SourceHandler.build_fetch_params_hook(batch)

        # Assert: hook is not None
        self.assertIsNotNone(hook)

        # Assert: hook injects the since clause
        params = {"$filter": "existing filter", "$orderby": "createdDateTime desc"}
        result = hook(params)
        self.assertIn("createdDateTime ge", result["$filter"])
        self.assertIn("2026-07-01T00:00:00", result["$filter"])

    def test_source_handler_build_fetch_params_hook_start_date(self):
        """Then DefenderO365SourceHandler.build_fetch_params_hook tries to extract
        the end_date, if not fallback to the start_date,
        from expectations and returns a hook that injects since_datetime."""
        # Build a mock expectation with end_date signature
        mock_expectation = MagicMock()
        mock_sig = MagicMock()
        mock_sig.type = SignatureTypes.SIG_TYPE_START_DATE
        mock_sig.value = "2026-07-01T00:00:00"
        mock_expectation.inject_expectation_signatures = [mock_sig]

        batch = [mock_expectation]

        # Execute
        hook = module.DefenderO365SourceHandler.build_fetch_params_hook(batch)

        # Assert: hook is not None
        self.assertIsNotNone(hook)

        # Assert: hook injects the since clause
        params = {"$filter": "existing filter", "$orderby": "createdDateTime desc"}
        result = hook(params)
        self.assertIn("createdDateTime ge", result["$filter"])
        self.assertIn("2026-07-01T00:00:00", result["$filter"])

    def test_source_handler_build_fetch_params_hook_neither(self):
        """Then DefenderO365SourceHandler.build_fetch_params_hook returns None
        when no end_date signatures are present."""
        # Build a mock expectation without end_date signature
        mock_expectation = MagicMock()
        mock_expectation.inject_expectation_signatures = []

        batch = [mock_expectation]

        # Execute
        hook = module.DefenderO365SourceHandler.build_fetch_params_hook(batch)

        # Assert: hook is None
        self.assertIsNone(hook)


if __name__ == "__main__":
    unittest.main()
