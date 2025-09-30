import unittest
from datetime import datetime
from test.fixtures.crowdstrike_alerts_v2 import (
    ALERT_DATA,
    GET_ALERTS_V2_FAILURE_RESPONSE,
    GET_ALERTS_V2_SUCCESS_RESPONSE,
    GET_ALERTS_V2_SUCCESS_RESPONSE_NO_ITEMS,
    GET_ALERTS_V2_SUCCESS_RESPONSE_WITH_MALFORMED_DATA,
    QUERY_ALERTS_V2_FAILURE_RESPONSE,
    QUERY_ALERTS_V2_SUCCESS_RESPONSE,
)
from test.fixtures.defaults import DEFAULT_SIGNATURE_TYPES, get_default_api_handler
from unittest.mock import patch

from pydantic import ValidationError
from pyoaev.exceptions import OpenAEVError
from pyoaev.signatures.signature_type import SignatureType
from pyoaev.signatures.types import MatchTypes, SignatureTypes

from crowdstrike.query_strategy.alert import Alert, Item


class TestAlert(unittest.TestCase):
    STRATEGY = Alert(api_handler=get_default_api_handler())

    @patch("falconpy.alerts.Alerts.query_alerts_v2")
    @patch("falconpy.alerts.Alerts.get_alerts_v2")
    def test_when_alerts_returned_they_are_correctly_formatted(
        self, mock_get_alerts, mock_query_alerts
    ):
        mock_query_alerts.return_value = QUERY_ALERTS_V2_SUCCESS_RESPONSE
        print("QUERY_ALERTS_V2_SUCCESS_RESPONSE", QUERY_ALERTS_V2_SUCCESS_RESPONSE)
        mock_get_alerts.return_value = GET_ALERTS_V2_SUCCESS_RESPONSE
        print("GET_ALERTS_V2_SUCCESS_RESPONSE", GET_ALERTS_V2_SUCCESS_RESPONSE)

        expected_values = ALERT_DATA

        print("expected_values", expected_values)
        actual_data = TestAlert.STRATEGY.get_raw_data(start_time=datetime.now())
        print("actual_data", actual_data)

        self.assertEqual(len(actual_data), len(expected_values))

        for alert in actual_data:
            self.assertIsNotNone(expected_values.get(alert.id))
            self.assertEqual(
                alert.get_hostname(), expected_values[alert.id]["hostname"]
            )
            self.assertEqual(
                alert.get_process_image_names(),
                expected_values[alert.id]["process_names"],
            )

    @patch("falconpy.alerts.Alerts.query_alerts_v2")
    @patch("falconpy.alerts.Alerts.get_alerts_v2")
    def test_when_alerts_returned_malformed_they_are_skipped(
        self, mock_get_alerts, mock_query_alerts
    ):
        mock_query_alerts.return_value = QUERY_ALERTS_V2_SUCCESS_RESPONSE
        mock_get_alerts.return_value = (
            GET_ALERTS_V2_SUCCESS_RESPONSE_WITH_MALFORMED_DATA
        )

        actual_data = TestAlert.STRATEGY.get_raw_data(start_time=datetime.now())

        self.assertFalse(any(actual_data))

    @patch("falconpy.alerts.Alerts.query_alerts_v2")
    def test_when_query_alerts_v2_error_return_no_items(self, mock_query_alerts):
        mock_query_alerts.return_value = QUERY_ALERTS_V2_FAILURE_RESPONSE

        actual_data = TestAlert.STRATEGY.get_raw_data(start_time=datetime.now())

        self.assertFalse(any(actual_data))

    @patch("falconpy.alerts.Alerts.query_alerts_v2")
    @patch("falconpy.alerts.Alerts.get_alerts_v2")
    def test_when_get_alerts_v2_error_return_no_items(
        self, mock_get_alerts, mock_query_alerts
    ):
        mock_query_alerts.return_value = QUERY_ALERTS_V2_SUCCESS_RESPONSE
        mock_get_alerts.return_value = GET_ALERTS_V2_FAILURE_RESPONSE

        actual_data = TestAlert.STRATEGY.get_raw_data(start_time=datetime.now())

        self.assertFalse(any(actual_data))

    @patch("falconpy.alerts.Alerts.query_alerts_v2")
    @patch("falconpy.alerts.Alerts.get_alerts_v2")
    def test_when_get_alerts_v2_returns_no_resource_return_no_items(
        self, mock_get_alerts, mock_query_alerts
    ):
        mock_query_alerts.return_value = QUERY_ALERTS_V2_SUCCESS_RESPONSE
        mock_get_alerts.return_value = GET_ALERTS_V2_SUCCESS_RESPONSE_NO_ITEMS

        actual_data = TestAlert.STRATEGY.get_raw_data(start_time=datetime.now())

        self.assertFalse(any(actual_data))

    # this test is arguably not extremely useful,
    # it effectively tests that we can't instantiate an invalid Item
    # therefore it's virtually impossible to accidentally pass an object
    # that would not respond to the contract
    def test_when_instantiating_invalid_item_throw(self):
        with self.assertRaises(ValidationError):
            Item(**{})

    def test_when_valid_alert_item_extract_process_names_as_expected(self):
        expected_process_name = "process.exe"
        expected_parent_process_name = "parent.exe"
        expected_grandparent_process_name = "grandparent.exe"
        expected_process_names = [
            expected_process_name,
            expected_parent_process_name,
            expected_grandparent_process_name,
        ]
        expected_display_name = "display name"
        expected_created_timestamp = "2025-01-01T00:00:00Z"
        expected_updated_timestamp = "2025-01-01T02:00:00Z"
        expected_composite_id = "composite_id"
        item = Item(
            **{
                "id": "alert_id",
                "device": {"hostname": "hostname.domain"},
                "filename": expected_process_name,
                "parent_details": {"filename": expected_parent_process_name},
                "grandparent_details": {"filename": expected_grandparent_process_name},
                "pattern_disposition": 0,
                "display_name": expected_display_name,
                "created_timestamp": expected_created_timestamp,
                "updated_timestamp": expected_updated_timestamp,
                "composite_id": expected_composite_id,
            }
        )

        actual = TestAlert.STRATEGY.extract_signature_data(
            item, SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME
        )

        self.assertEqual(actual, expected_process_names)

    def test_when_valid_alert_item_extract_unknown_signature_type_throws(self):
        item = Item(
            **{
                "id": "alert_id",
                "device": {"hostname": "hostname.domain"},
                "filename": "process.exe",
                "parent_details": {"filename": "parent.exe"},
                "grandparent_details": {"filename": "grandparent.exe"},
                "pattern_disposition": 0,
                "display_name": "display name",
                "created_timestamp": "2025-01-01T00:00:00Z",
                "updated_timestamp": "2025-01-01T02:00:00Z",
                "composite_id": "composite_id",
            }
        )

        with self.assertRaises(OpenAEVError):
            TestAlert.STRATEGY.extract_signature_data(
                # purposefully pass an arbitrary string instead of SignatureTypes enum item
                item,
                "deliberately unknown sig type",
            )

    def test_when_valid_alert_item_get_signature_data_as_expected(self):
        item = Item(
            **{
                "id": "alert id",
                "device": {"hostname": "hostname.domain"},
                "filename": "process.exe",
                "parent_details": {"filename": "parent.exe"},
                "grandparent_details": {"filename": "grandparent.exe"},
                "pattern_disposition": 0,
                "display_name": "display name",
                "created_timestamp": "2025-01-01T00:00:00Z",
                "updated_timestamp": "2025-01-01T02:00:00Z",
                "composite_id": "composite_id",
            }
        )

        expected_signature_types = DEFAULT_SIGNATURE_TYPES

        actual = TestAlert.STRATEGY.get_signature_data(item, expected_signature_types)

        self.assertEqual(len(actual), len(expected_signature_types))
        for signature_type in expected_signature_types:
            self.assertIsNotNone(actual.get(signature_type.label.value))

    def test_when_valid_alert_item_with_unsupported_signature_type_skips(self):
        item = Item(
            **{
                "id": "alert id",
                "device": {"hostname": "hostname.domain"},
                "filename": "process.exe",
                "parent_details": {"filename": "parent.exe"},
                "grandparent_details": {"filename": "grandparent.exe"},
                "pattern_disposition": 0,
                "display_name": "display name",
                "created_timestamp": "2025-01-01T00:00:00Z",
                "updated_timestamp": "2025-01-01T02:00:00Z",
                "composite_id": "composite_id",
            }
        )

        class _fake_signature:
            value: str

            def __init__(self, value):
                self.value = value

        unknown_type_label = "UNKNOWN_SIGNATURE_TYPE"
        expected_signature_types = DEFAULT_SIGNATURE_TYPES + [
            SignatureType(
                _fake_signature(value=unknown_type_label),
                match_type=MatchTypes.MATCH_TYPE_SIMPLE,
            )
        ]

        actual = TestAlert.STRATEGY.get_signature_data(item, expected_signature_types)

        self.assertNotEqual(len(actual), len(expected_signature_types))
        for signature_type in expected_signature_types:
            signature_data = actual.get(signature_type.label.value)
            if signature_type.label.value != unknown_type_label:
                self.assertIsNotNone(signature_data)
            else:
                self.assertIsNone(signature_data)


if __name__ == "__main__":
    unittest.main()
