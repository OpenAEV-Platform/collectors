"""Unit tests for DefenderDataFetcher.

Tests pagination, retry logic, auth recovery, evidence filtering,
and structured logging with mocked HTTP responses.
"""

import unittest
from unittest.mock import MagicMock

import src.source.source_handler as module


class TestDefenderSourceHandler(unittest.TestCase):
    """Test DefenderSourceHandler."""

    def test_base_source_handler_returns_none(self):
        """Then the base SourceHandler.build_fetch_params_hook returns None by default."""
        from src.collector.models.source import SourceHandler

        hook = SourceHandler.build_fetch_params_hook([])
        self.assertIsNone(hook)

    def test_source_handler_build_fetch_params_hook(self):
        """Then DefenderSourceHandler.build_fetch_params_hook extracts end_date
        from expectations and returns a hook that injects since_datetime."""
        # Build a mock expectation with end_date signature
        mock_expectation = MagicMock()
        mock_sig = MagicMock()
        mock_sig.type = module.SignatureTypes.SIG_TYPE_END_DATE
        mock_sig.value = "2026-07-01T00:00:00"
        mock_expectation.inject_expectation_signatures = [mock_sig]

        batch = [mock_expectation]

        # Execute
        hook = module.DefenderSourceHandler.build_fetch_params_hook(batch)

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
        # Build a mock expectation without end_date signature
        mock_expectation = MagicMock()
        mock_expectation.inject_expectation_signatures = []

        batch = [mock_expectation]

        # Execute
        hook = module.DefenderSourceHandler.build_fetch_params_hook(batch)

        # Assert: hook is None
        self.assertIsNone(hook)

    def test_source_handler_match_signature_groups_and_alert_data_parent_process_match(
        self,
    ):
        """
        Test case where the parent process match is enough to validate the match
        """
        value = "deadbeef"
        sigtype = module.SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME
        signature_groups = {sigtype: [{"type": sigtype, "value": value}]}
        alert_data = {sigtype: {"data": [value]}}
        oaev_detection_helper = MagicMock()

        match = module.DefenderSourceHandler.match_signature_groups_and_alert_data(
            signature_groups,
            alert_data,
            oaev_detection_helper,
        )

        self.assertTrue(match)
        oaev_detection_helper.assert_not_called()

    def test_source_handler_match_signature_groups_and_alert_data_parent_process_not_match(
        self,
    ):
        """
        Test case where the parent process match does not match
        """
        value = "deadbeef"
        other_value = "badc0fee"
        sigtype = module.SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME
        signature_groups = {sigtype: [{"type": sigtype, "value": value}]}
        alert_data = {sigtype: {"data": [other_value]}}
        oaev_detection_helper = MagicMock()

        match = module.DefenderSourceHandler.match_signature_groups_and_alert_data(
            signature_groups,
            alert_data,
            oaev_detection_helper,
        )

        self.assertFalse(match)
        oaev_detection_helper.assert_not_called()

    def test_source_handler_match_signature_groups_and_alert_data_file_name_not_enough(
        self,
    ):
        """
        Test case where the file name match but is not enough
        """
        value = "deadbeef"
        sigtype = module.SignatureTypes.SIG_TYPE_FILE_NAME
        signature_groups = {sigtype: [{"type": sigtype, "value": value}]}
        alert_data = {sigtype: {"data": [value]}}
        oaev_detection_helper = MagicMock()

        match = module.DefenderSourceHandler.match_signature_groups_and_alert_data(
            signature_groups,
            alert_data,
            oaev_detection_helper,
        )

        self.assertFalse(match)
        oaev_detection_helper.assert_not_called()

    def test_source_handler_match_signature_groups_and_alert_data_file_name_and_ip_match(
        self,
    ):
        """
        Test case where the file name match and the source IPv4 match, thus being enough
        """
        value = "deadbeef"
        sigtype = module.SignatureTypes.SIG_TYPE_FILE_NAME
        other_value = "badc0fee"
        other_sigtype = module.SignatureTypes.SIG_TYPE_SOURCE_IPV4_ADDRESS
        signature_groups = {
            sigtype: [{"type": sigtype, "value": value}],
            other_sigtype: [{"type": other_sigtype, "value": other_value}],
        }
        alert_data = {
            sigtype: {"data": [value]},
            other_sigtype: {"data": [other_value]},
        }
        oaev_detection_helper = MagicMock()

        match = module.DefenderSourceHandler.match_signature_groups_and_alert_data(
            signature_groups,
            alert_data,
            oaev_detection_helper,
        )

        self.assertTrue(match)
        oaev_detection_helper.assert_not_called()


if __name__ == "__main__":
    unittest.main()
