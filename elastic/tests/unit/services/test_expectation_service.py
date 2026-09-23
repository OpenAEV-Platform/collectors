import unittest
from unittest.mock import MagicMock, patch, sentinel

import src.services.expectation_service as module


class TestElasticExpectationService(unittest.TestCase):
    @patch.object(module, "ElasticClientAPI")
    def test_init_minimalist(self, m_elastic_client_api):
        config = MagicMock()
        config.elastic = None

        expectation_service = module.ElasticExpectationService(config)

        m_elastic_client_api.assert_called_with(config)
        self.assertIsInstance(expectation_service.converter, module.Converter)
        self.assertEqual(expectation_service.time_window, module.timedelta(hours=1))
        self.assertEqual(expectation_service.max_retry, 3)
        self.assertEqual(expectation_service.offset, 30)

    @patch.object(module, "ElasticClientAPI")
    def test_init_full_config(self, m_elastic_client_api):
        config = MagicMock()
        config_elastic = MagicMock()
        config_elastic.time_window = sentinel.time_window
        config_elastic.max_retry = sentinel.max_retry
        offset = MagicMock()
        config_elastic.offset = offset
        config.elastic = config_elastic

        expectation_service = module.ElasticExpectationService(config)

        m_elastic_client_api.assert_called_with(config)
        self.assertIsInstance(expectation_service.converter, module.Converter)
        self.assertEqual(expectation_service.time_window, sentinel.time_window)
        self.assertEqual(expectation_service.max_retry, sentinel.max_retry)
        self.assertEqual(expectation_service.offset, offset.total_seconds.return_value)

    @patch.object(module, "ElasticClientAPI")
    def test_init_configuration_error(self, m_elastic_client_api):
        config = MagicMock()
        config.elastic = None

        m_elastic_client_api.side_effect = module.ElasticConfigurationError

        with self.assertRaises(module.ElasticConfigurationError):
            module.ElasticExpectationService(config)
