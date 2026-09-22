import unittest
from unittest.mock import ANY, MagicMock, patch, sentinel

import src.source.source_handler as module


class TestDefenderO365SourceHandler(unittest.TestCase):
    @patch.object(module, "datetime")
    def test_build_fetch_params_hook(self, m_datetime):
        signature = MagicMock()
        signature.type = module.SignatureTypes.SIG_TYPE_END_DATE
        sig_value = MagicMock()
        signature.value = sig_value
        expectation = MagicMock()
        expectation.inject_expectation_signatures = [signature]
        batch = [expectation]
        dt = MagicMock()
        dt.tzinfo = "UTC"
        m_datetime.fromisoformat.return_value = dt

        module.DefenderO365SourceHandler.build_fetch_params_hook(batch)

        m_datetime.fromisoformat.assert_called_once_with(sig_value)
        dt.astimezone.assert_called_once_with(module.UTC)

    @patch.object(module, "datetime")
    def test_build_fetch_params_hook_with_error(self, m_datetime):
        signature = MagicMock()
        signature.type = module.SignatureTypes.SIG_TYPE_END_DATE
        sig_value = MagicMock()
        signature.value = sig_value
        expectation = MagicMock()
        expectation.inject_expectation_signatures = [signature, signature]
        batch = [expectation]
        dt = MagicMock()
        dt.tzinfo = "UTC"
        m_datetime.fromisoformat.side_effect = [ValueError, dt]

        module.DefenderO365SourceHandler.build_fetch_params_hook(batch)

        m_datetime.fromisoformat.assert_called_with(sig_value)
        dt.astimezone.assert_called_once_with(module.UTC)
