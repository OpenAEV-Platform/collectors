import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import src.collector.utils.expectation_utils as module
from pyoaev.signatures.types import SignatureTypes


class TestExpectationUtils(unittest.TestCase):
    def test_extract_end_date(self):
        date_str = "2031-01-02T03:04:05.060000+00:00"
        date = datetime.fromisoformat(date_str)

        not_end_date_signature = MagicMock()
        not_end_date_signature.type = SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME

        end_date_signature = MagicMock()
        end_date_signature.type = SignatureTypes.SIG_TYPE_END_DATE
        end_date_signature.value = date_str

        inject_expectation_signatures = [
            not_end_date_signature,
            end_date_signature,
        ]

        expectation = MagicMock()
        expectation.inject_expectation_signatures = inject_expectation_signatures

        end_date = module.extract_end_date(expectation)

        self.assertEqual(end_date, date)

    def test_extract_end_date_missing(self):
        not_end_date_signature = MagicMock()
        not_end_date_signature.type = SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME

        inject_expectation_signatures = [
            not_end_date_signature,
        ]

        expectation = MagicMock()
        expectation.inject_expectation_signatures = inject_expectation_signatures

        end_date = module.extract_end_date(expectation)

        self.assertIsNone(end_date)

    def test_time_window_over_no(self):
        end_date_signature = MagicMock()
        end_date_signature.type = SignatureTypes.SIG_TYPE_END_DATE
        end_date_signature.value = (
            datetime.now(UTC) - timedelta(minutes=1)
        ).isoformat()

        inject_expectation_signatures = [
            end_date_signature,
        ]

        expectation = MagicMock()
        expectation.inject_expectation_signatures = inject_expectation_signatures

        time_window = timedelta(minutes=10)

        self.assertFalse(module.time_window_over(expectation, time_window))

    def test_time_window_over_yes(self):
        end_date_signature = MagicMock()
        end_date_signature.type = SignatureTypes.SIG_TYPE_END_DATE
        end_date_signature.value = (
            datetime.now(UTC) - timedelta(minutes=15)
        ).isoformat()

        inject_expectation_signatures = [
            end_date_signature,
        ]

        expectation = MagicMock()
        expectation.inject_expectation_signatures = inject_expectation_signatures

        time_window = timedelta(minutes=2)

        self.assertTrue(module.time_window_over(expectation, time_window))

    def test_time_window_over_missing(self):
        not_end_date_signature = MagicMock()
        not_end_date_signature.type = SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME

        inject_expectation_signatures = [
            not_end_date_signature,
        ]

        expectation = MagicMock()
        expectation.inject_expectation_signatures = inject_expectation_signatures

        time_window = MagicMock()

        self.assertTrue(module.time_window_over(expectation, time_window))
