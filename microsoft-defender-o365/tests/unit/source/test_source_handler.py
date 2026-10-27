import unittest
from unittest.mock import MagicMock, patch

import src.source.source_handler as module


class TestDefenderO365SourceHandler(unittest.TestCase):
    @patch.object(module, "extract_end_date")
    def test_build_fetch_params_hook(self, m_extract_end_date):
        expectation = MagicMock()
        batch = [expectation]
        dt = MagicMock()
        m_extract_end_date.return_value = dt

        module.DefenderO365SourceHandler.build_fetch_params_hook(batch)

        m_extract_end_date.assert_called_once_with(expectation)
