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
        params = {"$filter": "existing filter", "$orderby": "lastUpdateDateTime desc"}
        result = hook(params)
        self.assertIn("lastUpdateDateTime ge", result["$filter"])
        self.assertIn("2026-07-01T00:00:00", result["$filter"])

    def test_source_handler_build_fetch_params_hook_both(self):
        """Then DefenderSourceHandler.build_fetch_params_hook extracts end_date
        from expectations and returns a hook that injects since_datetime."""
        # Build a mock expectation with end_date signature
        mock_expectation = MagicMock()
        mock_sig = MagicMock()
        mock_sig.type = module.SignatureTypes.SIG_TYPE_END_DATE
        mock_sig.value = "2026-07-04T00:00:00"
        mock_expectation.inject_expectation_signatures = [mock_sig]

        mock_expectation2 = MagicMock()
        mock_sig2 = MagicMock()
        mock_sig2.type = module.SignatureTypes.SIG_TYPE_END_DATE
        mock_sig2.value = "2026-07-01T00:00:00"
        mock_expectation2.inject_expectation_signatures = [mock_sig2]

        batch = [mock_expectation, mock_expectation2]

        # Execute
        hook = module.DefenderSourceHandler.build_fetch_params_hook(batch)

        # Assert: hook is not None
        self.assertIsNotNone(hook)

        # Assert: hook injects the since clause
        params = {"$filter": "existing filter", "$orderby": "lastUpdateDateTime desc"}
        result = hook(params)
        self.assertIn("lastUpdateDateTime ge", result["$filter"])
        self.assertIn("2026-07-01T00:00:00", result["$filter"])

    def test_source_handler_build_fetch_params_hook_start_date(self):
        """Then DefenderSourceHandler.build_fetch_params_hook tries to extract
        the end_date, if not fallback to the start_date,
        from expectations and returns a hook that injects since_datetime."""
        # Build a mock expectation with end_date signature
        mock_expectation = MagicMock()
        mock_sig = MagicMock()
        mock_sig.type = module.SignatureTypes.SIG_TYPE_START_DATE
        mock_sig.value = "2026-07-01T00:00:00"
        mock_expectation.inject_expectation_signatures = [mock_sig]

        batch = [mock_expectation]

        # Execute
        hook = module.DefenderSourceHandler.build_fetch_params_hook(batch)

        # Assert: hook is not None
        self.assertIsNotNone(hook)

        # Assert: hook injects the since clause
        params = {"$filter": "existing filter", "$orderby": "lastUpdateDateTime desc"}
        result = hook(params)
        self.assertIn("lastUpdateDateTime ge", result["$filter"])
        self.assertIn("2026-07-01T00:00:00", result["$filter"])

    def test_source_handler_build_fetch_params_hook_neither(self):
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
        Test case where the parent process match is enough to validate the match.
        Also testing the relax matching case at the same type.
        """
        signature_value = "deadbeef"
        alert_value = "deadbeef.exe"
        sigtype = module.SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME
        signature_groups = {sigtype: [{"type": sigtype, "value": signature_value}]}
        alert_data = {sigtype: {"data": [alert_value]}}
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


def _alert(status, evidence):
    from src.source.source_data import Alert

    return Alert(
        id="my-id",
        title="this is a title",
        status=status,
        serviceSource="microsoftDefenderForEndpoint",
        alertWebUrl="http://endpoint.tld",
        lastActivityDateTime="1987-06-05T04:02:55.1",
        lastUpdateDateTime="1987-06-05T04:03:02.1",
        evidence=evidence,
    )


def _process(name, status, **extra):
    return {
        "@odata.type": "#microsoft.graph.security.processEvidence",
        "detectionStatus": status,
        "imageFile": {"fileName": name},
        **extra,
    }


class TestDefenderPreventionMatching(unittest.TestCase):
    """Prevention is validated only by evidence correlated to the implant (#675)."""

    IMPLANT = "oaev-implant-4f46361a-agent-294c2457"

    def _expectation(self, expectation_type=None):
        expectation_type = expectation_type or module.PreventionExpectation
        signature = MagicMock(
            type=module.SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
            value=self.IMPLANT,
        )
        return MagicMock(
            spec=expectation_type, inject_expectation_signatures=[signature]
        )

    def _match(self, alert, expectation=None):
        return module.DefenderSourceHandler.match_expectation_and_sourcedata(
            expectation or self._expectation(), alert
        )

    def test_unrelated_process_blocked_is_not_prevented(self):
        alert = _alert(
            "new",
            [
                _process(f"{self.IMPLANT}.exe", "detected", remediationStatus="active"),
                _process("unrelated.exe", "blocked", remediationStatus="blocked"),
            ],
        )
        self.assertEqual(self._match(alert), (False, False))

    def test_expected_process_blocked_is_prevented(self):
        alert = _alert(
            "new",
            [
                _process(f"{self.IMPLANT}.exe", "blocked"),
                _process("unrelated.exe", "detected"),
            ],
        )
        self.assertEqual(self._match(alert), (True, True))

    def test_blocked_child_of_the_implant_is_prevented(self):
        alert = _alert(
            "new",
            [
                _process(
                    f"{self.IMPLANT}.exe", "detected", processId=10, mdeDeviceId="d"
                ),
                _process(
                    "reg.exe",
                    "detected",
                    remediationStatus="prevented",
                    processId=11,
                    parentProcessId=10,
                    mdeDeviceId="d",
                ),
            ],
        )
        self.assertEqual(self._match(alert), (True, True))

    def test_blocked_file_of_the_implant_is_prevented(self):
        alert = _alert(
            "new",
            [
                {
                    "@odata.type": "#microsoft.graph.security.fileEvidence",
                    "detectionStatus": "prevented",
                    "fileDetails": {"fileName": f"{self.IMPLANT}.exe"},
                },
            ],
        )
        self.assertEqual(self._match(alert), (True, True))

    def test_nothing_blocked_is_not_prevented(self):
        alert = _alert("new", [_process(f"{self.IMPLANT}.exe", "detected")])
        self.assertEqual(self._match(alert), (False, False))

    def test_handled_alert_stays_prevented(self):
        alert = _alert("resolved", [_process(f"{self.IMPLANT}.exe", "detected")])
        self.assertEqual(self._match(alert), (True, True))

    def test_detection_is_unchanged(self):
        alert = _alert("new", [_process("unrelated.exe", "blocked")])
        self.assertEqual(
            self._match(alert, self._expectation(module.DetectionExpectation)),
            (True, False),
        )


if __name__ == "__main__":
    unittest.main()
