import unittest
from unittest.mock import MagicMock, patch, sentinel

import src.services.expectation_service as module


class TestSplunkESExpectationService(unittest.TestCase):
    @patch.object(module, "SplunkESClientAPI")
    def test_init_minimalist(self, m_splunk_es_client_api):
        config = MagicMock()
        config.splunk_es = None

        expectation_service = module.SplunkESExpectationService(config)

        m_splunk_es_client_api.assert_called_with(config)
        self.assertIsInstance(expectation_service.converter, module.Converter)
        self.assertIsInstance(
            expectation_service.parent_process_parser, module.ParentProcessParser
        )
        self.assertIsInstance(
            expectation_service._regex_engine, module.RegexSignatureEngine
        )
        self.assertEqual(expectation_service.time_window, module.timedelta(hours=1))
        self.assertEqual(expectation_service.max_retry, 3)
        self.assertEqual(expectation_service.offset, 30)

    @patch.object(module, "SplunkESClientAPI")
    def test_init_full_config(self, m_splunk_es_client_api):
        config = MagicMock()
        config_splunk_es = MagicMock()
        config_splunk_es.time_window = sentinel.time_window
        config_splunk_es.max_retry = sentinel.max_retry
        offset = MagicMock()
        config_splunk_es.offset = offset
        config.splunk_es = config_splunk_es

        expectation_service = module.SplunkESExpectationService(config)

        m_splunk_es_client_api.assert_called_with(config)
        self.assertIsInstance(expectation_service.converter, module.Converter)
        self.assertIsInstance(
            expectation_service.parent_process_parser, module.ParentProcessParser
        )
        self.assertIsInstance(
            expectation_service._regex_engine, module.RegexSignatureEngine
        )
        self.assertEqual(expectation_service.time_window, sentinel.time_window)
        self.assertEqual(expectation_service.max_retry, sentinel.max_retry)
        self.assertEqual(expectation_service.offset, offset.total_seconds.return_value)

    @patch.object(module, "SplunkESClientAPI")
    def test_init_configuration_error(self, m_splunk_es_client_api):
        config = MagicMock()
        config.splunk_es = None

        m_splunk_es_client_api.side_effect = module.SplunkESConfigurationError

        with self.assertRaises(module.SplunkESConfigurationError):
            module.SplunkESExpectationService(config)
