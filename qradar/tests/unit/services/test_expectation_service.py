import unittest
from unittest.mock import MagicMock, patch, sentinel

import src.services.expectation_service as module


class TestQRadarExpectationService(unittest.TestCase):
    @patch.object(module, "QRadarClientAPI")
    def test_init_minimal_config(self, m_qradar_client_api):
        config = MagicMock()
        config.qradar = None

        expectation_service = module.QRadarExpectationService(config)

        self.assertEqual(expectation_service.config, config)
        m_qradar_client_api.assert_called_with(config)
        self.assertEqual(
            expectation_service.client_api, m_qradar_client_api.return_value
        )
        self.assertIsInstance(expectation_service.converter, module.Converter)
        self.assertEqual(expectation_service.time_window, module.timedelta(hours=1))
        self.assertEqual(expectation_service.max_retry, 3)
        self.assertEqual(expectation_service.offset, 30)

    @patch.object(module, "QRadarClientAPI")
    def test_init_full_config(self, m_qradar_client_api):
        config_qradar = MagicMock()
        config_qradar.time_window = sentinel.time_window
        config_qradar.max_retry = sentinel.max_retry
        offset = MagicMock()
        config_qradar.offset = offset
        config = MagicMock()
        config.qradar = config_qradar

        expectation_service = module.QRadarExpectationService(config)

        self.assertEqual(expectation_service.config, config)
        m_qradar_client_api.assert_called_with(config)
        self.assertEqual(
            expectation_service.client_api, m_qradar_client_api.return_value
        )
        self.assertIsInstance(expectation_service.converter, module.Converter)
        self.assertEqual(expectation_service.time_window, sentinel.time_window)
        self.assertEqual(expectation_service.max_retry, sentinel.max_retry)
        self.assertEqual(expectation_service.offset, offset.total_seconds.return_value)

    @patch.object(module, "QRadarClientAPI")
    def test_init_configuration_error(self, m_qradar_client_api):
        config = MagicMock()
        config.qradar = None
        m_qradar_client_api.side_effect = module.QRadarConfigurationError

        with self.assertRaises(module.QRadarConfigurationError):
            module.QRadarExpectationService(config)
            m_qradar_client_api.assert_called_with(config)
