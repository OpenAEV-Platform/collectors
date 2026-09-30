import unittest
from unittest.mock import MagicMock, patch

import src.services.utils.signature_extractor as module


class TestSignatureExtractor(unittest.TestCase):
    @patch.object(module, "datetime")
    def test_extract_end_date_empty(self, m_datetime):
        batch = []

        end_date = module.SignatureExtractor.extract_end_date(batch)

        self.assertIsNone(end_date)

    @patch.object(module, "datetime")
    def test_extract_end_date_match(self, m_datetime):
        expectation = MagicMock()
        signature = MagicMock()
        sig_type = MagicMock()
        sig_type.value = "end_date"
        signature.type = sig_type
        sig_value = MagicMock()
        signature.value = sig_value
        expectation.inject_expectation_signatures = [signature]
        batch = [expectation]

        end_date = module.SignatureExtractor.extract_end_date(batch)

        m_datetime.fromisoformat.assert_called_with(sig_value.replace.return_value)
        self.assertEqual(end_date, m_datetime.fromisoformat.return_value)

    @patch.object(module, "datetime")
    def test_extract_end_date_fail(self, m_datetime):
        expectation = MagicMock()
        signature = MagicMock()
        sig_type = MagicMock()
        sig_type.value = "end_date"
        signature.type = sig_type
        sig_value = MagicMock()
        signature.value = sig_value
        expectation.inject_expectation_signatures = [signature]
        batch = [expectation]
        m_datetime.fromisoformat.side_effect = ValueError

        end_date = module.SignatureExtractor.extract_end_date(batch)

        m_datetime.fromisoformat.assert_called_with(sig_value.replace.return_value)
        self.assertIsNone(end_date)
