import unittest
from unittest.mock import patch

from tests.fixtures.crowdstrike_alerts_v2 import MOCKED_ALERT
from tests.fixtures.defaults import (
    TestStrategy,
    get_default_api_handler,
    get_default_collector,
)

from crowdstrike.query_strategy.alert import Alert, Item


class TestOpenAEVCrowdstrike(unittest.TestCase):
    @patch("pyoaev.apis.InjectExpectationManager.update")
    def test_when_alert_matches_update_prevention_expectation(
        self, mock_expectation_update
    ):
        expected_expectation_id = "expectation_id"
        expectations = [
            {
                "inject_expectation_type": "PREVENTION",
                "inject_expectation_id": expected_expectation_id,
                "inject_expectation_signatures": [
                    {"type": "parent_process_name", "value": "grandparent.exe"},
                ],
                "inject_expectation_results": {},
            }
        ]

        signature_data = {
            "parent_process_name": {
                "type": "fuzzy",
                "data": ["grandparent.exe", "some_process.exe"],
                "score": 95,
            },
        }

        strategy = TestStrategy(
            raw_data_callback=lambda: None,
            signature_data_callback=lambda: signature_data,
            is_prevented_callback=lambda: True,
            get_alert_id_callback=lambda: expected_expectation_id,
        )

        collector = get_default_collector(strategy)

        traces = collector._match_expectations([Item(**MOCKED_ALERT)], expectations)

        mock_expectation_update.assert_called_once_with(
            expected_expectation_id,
            {
                "collector_id": collector._configuration.get("collector_id"),
                "result": "Prevented",
                "is_success": True,
                "metadata": {"alertId": expected_expectation_id},
            },
        )
        self.assertEqual(1, len(traces))
        self.assertEqual(
            traces[0],
            {
                "inject_expectation_trace_expectation": expected_expectation_id,
                "inject_expectation_trace_source_id": collector._configuration.get(
                    "collector_id"
                ),
                "inject_expectation_trace_alert_name": MOCKED_ALERT["display_name"],
                "inject_expectation_trace_alert_link": collector._configuration.get(
                    "crowdstrike_ui_base_url"
                )
                + "/unified-detections/"
                + MOCKED_ALERT["composite_id"],
                "inject_expectation_trace_date": MOCKED_ALERT["updated_timestamp"],
            },
        )

    @patch("pyoaev.apis.InjectExpectationManager.update")
    def test_when_alert_matches_but_not_prevented_update_prevention_expectation(
        self, mock_expectation_update
    ):
        expected_expectation_id = "expectation_id"
        expectations = [
            {
                "inject_expectation_type": "PREVENTION",
                "inject_expectation_id": expected_expectation_id,
                "inject_expectation_signatures": [
                    {"type": "parent_process_name", "value": "grandparent.exe"},
                ],
                "inject_expectation_results": {},
            }
        ]

        signature_data = {
            "parent_process_name": {
                "type": "fuzzy",
                "data": ["grandparent.exe", "some_process.exe"],
                "score": 95,
            },
        }

        strategy = TestStrategy(
            raw_data_callback=lambda: None,
            signature_data_callback=lambda: signature_data,
            is_prevented_callback=lambda: False,
            get_alert_id_callback=lambda: expected_expectation_id,
        )

        collector = get_default_collector(strategy)

        traces = collector._match_expectations([Item(**MOCKED_ALERT)], expectations)

        mock_expectation_update.assert_called_once_with(
            expected_expectation_id,
            {
                "collector_id": collector._configuration.get("collector_id"),
                "result": "Not Prevented",
                "is_success": False,
                "metadata": {"alertId": expected_expectation_id},
            },
        )

        self.assertEqual(1, len(traces))
        self.assertEqual(
            traces[0],
            {
                "inject_expectation_trace_expectation": expected_expectation_id,
                "inject_expectation_trace_source_id": collector._configuration.get(
                    "collector_id"
                ),
                "inject_expectation_trace_alert_name": MOCKED_ALERT["display_name"],
                "inject_expectation_trace_alert_link": collector._configuration.get(
                    "crowdstrike_ui_base_url"
                )
                + "/unified-detections/"
                + MOCKED_ALERT["composite_id"],
                "inject_expectation_trace_date": MOCKED_ALERT["updated_timestamp"],
            },
        )

    @patch("pyoaev.apis.InjectExpectationManager.update")
    def test_when_alert_matches_update_detection_expectation(
        self, mock_expectation_update
    ):
        expected_expectation_id = "expectation_id"
        expectations = [
            {
                "inject_expectation_type": "DETECTION",
                "inject_expectation_id": expected_expectation_id,
                "inject_expectation_signatures": [
                    {"type": "parent_process_name", "value": "grandparent.exe"},
                ],
                "inject_expectation_results": {},
            }
        ]

        signature_data = {
            "parent_process_name": {
                "type": "fuzzy",
                "data": ["grandparent.exe", "some_process.exe"],
                "score": 95,
            },
        }

        strategy = TestStrategy(
            raw_data_callback=lambda: None,
            signature_data_callback=lambda: signature_data,
            is_prevented_callback=lambda: True,
            get_alert_id_callback=lambda: expected_expectation_id,
        )

        collector = get_default_collector(strategy)

        traces = collector._match_expectations([Item(**MOCKED_ALERT)], expectations)

        mock_expectation_update.assert_called_once_with(
            expected_expectation_id,
            {
                "collector_id": collector._configuration.get("collector_id"),
                "result": "Detected",
                "is_success": True,
                "metadata": {"alertId": expected_expectation_id},
            },
        )

        self.assertEqual(1, len(traces))
        self.assertEqual(
            traces[0],
            {
                "inject_expectation_trace_expectation": expected_expectation_id,
                "inject_expectation_trace_source_id": collector._configuration.get(
                    "collector_id"
                ),
                "inject_expectation_trace_alert_name": MOCKED_ALERT["display_name"],
                "inject_expectation_trace_alert_link": collector._configuration.get(
                    "crowdstrike_ui_base_url"
                )
                + "/unified-detections/"
                + MOCKED_ALERT["composite_id"],
                "inject_expectation_trace_date": MOCKED_ALERT["updated_timestamp"],
            },
        )

    @patch("pyoaev.apis.InjectExpectationManager.update")
    def test_when_expectation_has_expected_hostname_signature_ignore_it(
        self, mock_expectation_update
    ):
        expected_expectation_id = "expectation_id"
        expectations = [
            {
                "inject_expectation_type": "DETECTION",
                "inject_expectation_id": expected_expectation_id,
                "inject_expectation_signatures": [
                    {"type": "parent_process_name", "value": "grandparent.exe"},
                    {"type": "hostname", "value": "some_host"},
                ],
                "inject_expectation_results": {},
            }
        ]

        signature_data = {
            "parent_process_name": {
                "type": "fuzzy",
                "data": ["grandparent.exe", "some_process.exe"],
                "score": 95,
            },
        }

        strategy = TestStrategy(
            raw_data_callback=lambda: None,
            signature_data_callback=lambda: signature_data,
            is_prevented_callback=lambda: True,
            get_alert_id_callback=lambda: expected_expectation_id,
        )

        collector = get_default_collector(strategy)

        traces = collector._match_expectations([Item(**MOCKED_ALERT)], expectations)

        mock_expectation_update.assert_called_once_with(
            expected_expectation_id,
            {
                "collector_id": collector._configuration.get("collector_id"),
                "result": "Detected",
                "is_success": True,
                "metadata": {"alertId": expected_expectation_id},
            },
        )

        self.assertEqual(1, len(traces))
        self.assertEqual(
            traces[0],
            {
                "inject_expectation_trace_expectation": expected_expectation_id,
                "inject_expectation_trace_source_id": collector._configuration.get(
                    "collector_id"
                ),
                "inject_expectation_trace_alert_name": MOCKED_ALERT["display_name"],
                "inject_expectation_trace_alert_link": collector._configuration.get(
                    "crowdstrike_ui_base_url"
                )
                + "/unified-detections/"
                + MOCKED_ALERT["composite_id"],
                "inject_expectation_trace_date": MOCKED_ALERT["updated_timestamp"],
            },
        )

    @patch("pyoaev.apis.InjectExpectationManager.update")
    def test_when_alert_fails_to_match_dont_update_prevention_expectation(
        self, mock_expectation_update
    ):
        expected_expectation_id = "expectation_id"
        expectations = [
            {
                "inject_expectation_type": "PREVENTION",
                "inject_expectation_id": expected_expectation_id,
                "inject_expectation_signatures": [
                    {"type": "parent_process_name", "value": "unknown_process.exe"},
                ],
                "inject_expectation_results": {},
            }
        ]

        signature_data = {
            "parent_process_name": {
                "type": "fuzzy",
                "data": ["grandparent.exe", "some_process.exe"],
                "score": 95,
            },
        }

        strategy = TestStrategy(
            raw_data_callback=lambda: None,
            signature_data_callback=lambda: signature_data,
            is_prevented_callback=lambda: False,
            get_alert_id_callback=lambda: expected_expectation_id,
        )

        collector = get_default_collector(strategy)

        traces = collector._match_expectations([Item(**MOCKED_ALERT)], expectations)

        mock_expectation_update.assert_not_called()
        self.assertEqual(0, len(traces))

    @patch("pyoaev.apis.InjectExpectationManager.update")
    def test_when_signatures_match_when_unknown_expectation_type_skip_updating_expectation(
        self, mock_expectation_update
    ):
        expected_expectation_id = "expectation_id"
        expectations = [
            {
                "inject_expectation_type": "SOME UNKNOWN EXPECTATION TYPE",
                "inject_expectation_id": expected_expectation_id,
                "inject_expectation_signatures": [
                    {"type": "parent_process_name", "value": "grandparent.exe"},
                ],
                "inject_expectation_results": {},
            }
        ]

        signature_data = {
            "parent_process_name": {
                "type": "fuzzy",
                "data": ["grandparent.exe", "some_process.exe"],
                "score": 95,
            },
        }

        strategy = TestStrategy(
            raw_data_callback=lambda: None,
            signature_data_callback=lambda: signature_data,
            is_prevented_callback=lambda: True,
            get_alert_id_callback=lambda: expected_expectation_id,
        )

        collector = get_default_collector(strategy)

        traces = collector._match_expectations([Item(**MOCKED_ALERT)], expectations)

        mock_expectation_update.assert_not_called()

        self.assertEqual(0, len(traces))

    @patch("pyoaev.apis.InjectExpectationManager.update")
    def test_when_several_alerts_match_and_one_is_prevented_update_prevention_expectation_once(
        self, mock_expectation_update
    ):
        expected_expectation_id = "expectation_id"
        expectations = [
            {
                "inject_expectation_type": "PREVENTION",
                "inject_expectation_id": expected_expectation_id,
                "inject_expectation_signatures": [
                    {"type": "parent_process_name", "value": "grandparent.exe"},
                ],
                "inject_expectation_results": {},
            }
        ]
        # the prevented alert is neither the first nor the last matching alert
        alerts = [
            Item(**{**MOCKED_ALERT, "id": "detected_1", "pattern_disposition": 0}),
            Item(**{**MOCKED_ALERT, "id": "prevented", "pattern_disposition": 2048}),
            Item(**{**MOCKED_ALERT, "id": "detected_2", "pattern_disposition": 0}),
        ]

        collector = get_default_collector(Alert(api_handler=get_default_api_handler()))

        traces = collector._match_expectations(alerts, expectations)

        mock_expectation_update.assert_called_once_with(
            expected_expectation_id,
            {
                "collector_id": collector._configuration.get("collector_id"),
                "result": "Prevented",
                "is_success": True,
                "metadata": {"alertId": "prevented"},
            },
        )
        self.assertEqual(3, len(traces))

    @patch("pyoaev.apis.InjectExpectationManager.update")
    def test_when_several_alerts_match_and_none_is_prevented_update_prevention_expectation_once(
        self, mock_expectation_update
    ):
        expected_expectation_id = "expectation_id"
        expectations = [
            {
                "inject_expectation_type": "PREVENTION",
                "inject_expectation_id": expected_expectation_id,
                "inject_expectation_signatures": [
                    {"type": "parent_process_name", "value": "grandparent.exe"},
                ],
                "inject_expectation_results": {},
            }
        ]
        alerts = [
            Item(**{**MOCKED_ALERT, "id": "detected_1", "pattern_disposition": 0}),
            Item(**{**MOCKED_ALERT, "id": "detected_2", "pattern_disposition": 0}),
        ]

        collector = get_default_collector(Alert(api_handler=get_default_api_handler()))

        traces = collector._match_expectations(alerts, expectations)

        mock_expectation_update.assert_called_once_with(
            expected_expectation_id,
            {
                "collector_id": collector._configuration.get("collector_id"),
                "result": "Not Prevented",
                "is_success": False,
                "metadata": {"alertId": "detected_1"},
            },
        )
        self.assertEqual(2, len(traces))


if __name__ == "__main__":
    unittest.main()
