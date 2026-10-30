import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import src.collector.utils.expectation_utils as module
from pyoaev.signatures.types import SignatureTypes


class TestExpectationUtils(unittest.TestCase):
    def test_detect_date_both(self):
        end_date_signature = MagicMock()
        end_date_signature.type = SignatureTypes.SIG_TYPE_END_DATE
        start_date_signature = MagicMock()
        start_date_signature.type = SignatureTypes.SIG_TYPE_START_DATE
        not_date_signature = MagicMock()
        not_date_signature.type = SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME

        inject_expectation_signatures = [
            end_date_signature,
            start_date_signature,
            not_date_signature,
        ]

        expectation = MagicMock()
        expectation.inject_expectation_signatures = inject_expectation_signatures

        flag = module.detect_date(expectation)

        self.assertTrue(flag)

    def test_detect_date_end(self):
        end_date_signature = MagicMock()
        end_date_signature.type = SignatureTypes.SIG_TYPE_END_DATE
        not_date_signature = MagicMock()
        not_date_signature.type = SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME

        inject_expectation_signatures = [
            end_date_signature,
            not_date_signature,
        ]

        expectation = MagicMock()
        expectation.inject_expectation_signatures = inject_expectation_signatures

        flag = module.detect_date(expectation)

        self.assertTrue(flag)

    def test_detect_date_start(self):
        start_date_signature = MagicMock()
        start_date_signature.type = SignatureTypes.SIG_TYPE_START_DATE
        not_date_signature = MagicMock()
        not_date_signature.type = SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME

        inject_expectation_signatures = [
            start_date_signature,
            not_date_signature,
        ]

        expectation = MagicMock()
        expectation.inject_expectation_signatures = inject_expectation_signatures

        flag = module.detect_date(expectation)

        self.assertTrue(flag)

    def test_detect_date_neither(self):
        not_date_signature = MagicMock()
        not_date_signature.type = SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME

        inject_expectation_signatures = [
            not_date_signature,
        ]

        expectation = MagicMock()
        expectation.inject_expectation_signatures = inject_expectation_signatures

        flag = module.detect_date(expectation)

        self.assertFalse(flag)

    def test_extract_date(self):
        not_end_date_signature = MagicMock()
        not_end_date_signature.type = SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME

        end_date_str = "2031-01-02T03:04:05.060000+00:00"
        end_date = datetime.fromisoformat(end_date_str)
        end_date_signature = MagicMock()
        end_date_signature.type = SignatureTypes.SIG_TYPE_END_DATE
        end_date_signature.value = end_date_str

        start_date_str = "2031-01-02T01:02:03.040000+00:00"
        start_date = datetime.fromisoformat(start_date_str)
        start_date_signature = MagicMock()
        start_date_signature.type = SignatureTypes.SIG_TYPE_START_DATE
        start_date_signature.value = start_date_str

        inject_expectation_signatures = [
            not_end_date_signature,
            end_date_signature,
            start_date_signature,
        ]

        expectation = MagicMock()
        expectation.inject_expectation_signatures = inject_expectation_signatures

        date = module.extract_date(expectation, SignatureTypes.SIG_TYPE_END_DATE)

        self.assertEqual(date, end_date)

        date = module.extract_date(expectation, SignatureTypes.SIG_TYPE_START_DATE)

        self.assertEqual(date, start_date)

        expectation = MagicMock()
        expectation.inject_expectation_signatures = []

        date = module.extract_date(expectation, SignatureTypes.SIG_TYPE_END_DATE)

        self.assertIsNone(date)

    @patch.object(module, "extract_date")
    def test_extract_end_date(self, m_extract_date):
        expectation = MagicMock()

        end_date = module.extract_end_date(expectation)

        m_extract_date.assert_called_once_with(
            expectation, SignatureTypes.SIG_TYPE_END_DATE
        )
        self.assertEqual(end_date, m_extract_date.return_value)

    @patch.object(module, "extract_date")
    def test_extract_start_date(self, m_extract_date):
        expectation = MagicMock()

        start_date = module.extract_start_date(expectation)

        m_extract_date.assert_called_once_with(
            expectation, SignatureTypes.SIG_TYPE_START_DATE
        )
        self.assertEqual(start_date, m_extract_date.return_value)

    @patch.object(module, "extract_start_date")
    @patch.object(module, "extract_end_date")
    def test_extract_date_with_fallback_end(
        self, m_extract_end_date, m_extract_start_date
    ):
        end_date = MagicMock()
        m_extract_end_date.return_value = end_date
        expectation = MagicMock()

        date = module.extract_date_with_fallback(expectation)

        m_extract_end_date.assert_called_once_with(expectation)
        m_extract_start_date.assert_not_called()
        self.assertEqual(end_date, date)

    @patch.object(module, "extract_start_date")
    @patch.object(module, "extract_end_date")
    def test_extract_date_with_fallback_start(
        self, m_extract_end_date, m_extract_start_date
    ):
        m_extract_end_date.return_value = None
        start_date = MagicMock()
        m_extract_start_date.return_value = start_date
        expectation = MagicMock()

        date = module.extract_date_with_fallback(expectation)

        m_extract_end_date.assert_called_once_with(expectation)
        m_extract_start_date.assert_called_once_with(expectation)
        self.assertEqual(start_date, date)

    @patch.object(module, "extract_start_date")
    @patch.object(module, "extract_end_date")
    def test_extract_date_with_fallback_neither(
        self, m_extract_end_date, m_extract_start_date
    ):
        m_extract_end_date.return_value = None
        m_extract_start_date.return_value = None
        expectation = MagicMock()

        date = module.extract_date_with_fallback(expectation)

        m_extract_end_date.assert_called_once_with(expectation)
        m_extract_start_date.assert_called_once_with(expectation)
        self.assertIsNone(date)

    def test_time_window_over_no_for_end(self):
        end_date_signature = MagicMock()
        end_date_signature.type = SignatureTypes.SIG_TYPE_END_DATE
        end_date_signature.value = (
            datetime.now(UTC) - timedelta(minutes=1)
        ).isoformat()

        start_date_signature = MagicMock()
        start_date_signature.type = SignatureTypes.SIG_TYPE_START_DATE
        start_date_signature.value = (
            datetime.now(UTC) - timedelta(minutes=10)
        ).isoformat()

        inject_expectation_signatures = [
            end_date_signature,
            start_date_signature,
        ]

        expectation = MagicMock()
        expectation.inject_expectation_signatures = inject_expectation_signatures

        time_window = timedelta(minutes=10)

        self.assertFalse(module.time_window_over(expectation, time_window))

    def test_time_window_over_yes_for_end(self):
        end_date_signature = MagicMock()
        end_date_signature.type = SignatureTypes.SIG_TYPE_END_DATE
        end_date_signature.value = (
            datetime.now(UTC) - timedelta(minutes=15)
        ).isoformat()

        start_date_signature = MagicMock()
        start_date_signature.type = SignatureTypes.SIG_TYPE_START_DATE
        start_date_signature.value = (
            datetime.now(UTC) - timedelta(minutes=30)
        ).isoformat()

        inject_expectation_signatures = [
            end_date_signature,
            start_date_signature,
        ]

        expectation = MagicMock()
        expectation.inject_expectation_signatures = inject_expectation_signatures

        time_window = timedelta(minutes=2)

        self.assertTrue(module.time_window_over(expectation, time_window))

    def test_time_window_over_no_for_start(self):
        start_date_signature = MagicMock()
        start_date_signature.type = SignatureTypes.SIG_TYPE_START_DATE
        start_date_signature.value = (
            datetime.now(UTC) - timedelta(minutes=10)
        ).isoformat()

        inject_expectation_signatures = [
            start_date_signature,
        ]

        expectation = MagicMock()
        expectation.inject_expectation_signatures = inject_expectation_signatures

        time_window = timedelta(minutes=10)

        self.assertFalse(module.time_window_over(expectation, time_window))

    def test_time_window_over_yes_for_start(self):
        start_date_signature = MagicMock()
        start_date_signature.type = SignatureTypes.SIG_TYPE_START_DATE
        start_date_signature.value = (
            datetime.now(UTC) - timedelta(minutes=20)
        ).isoformat()

        inject_expectation_signatures = [
            start_date_signature,
        ]

        expectation = MagicMock()
        expectation.inject_expectation_signatures = inject_expectation_signatures

        time_window = timedelta(minutes=10)

        self.assertTrue(module.time_window_over(expectation, time_window))

    def test_time_window_over_missing_both(self):
        not_end_date_signature = MagicMock()
        not_end_date_signature.type = SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME

        inject_expectation_signatures = [
            not_end_date_signature,
        ]

        expectation = MagicMock()
        expectation.inject_expectation_signatures = inject_expectation_signatures

        time_window = MagicMock()

        self.assertFalse(module.time_window_over(expectation, time_window))
