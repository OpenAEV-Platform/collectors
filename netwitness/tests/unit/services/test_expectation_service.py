import unittest
from unittest.mock import MagicMock, patch, sentinel

import src.services.expectation_service as module


class TestNetWitnessExpectationService(unittest.TestCase):
    @patch.object(module, "NetWitnessClientAPI")
    def test_init_minimal_config(self, m_netwitness_client_api):
        config = MagicMock()
        config.netwitness = None

        expectation_service = module.NetWitnessExpectationService(config)

        self.assertEqual(expectation_service.config, config)
        m_netwitness_client_api.assert_called_with(config)
        self.assertEqual(
            expectation_service.client_api, m_netwitness_client_api.return_value
        )
        self.assertIsInstance(expectation_service.converter, module.Converter)
        self.assertEqual(expectation_service.time_window, module.timedelta(hours=1))
        self.assertEqual(expectation_service.max_retry, 3)
        self.assertEqual(expectation_service.offset, 30)

    @patch.object(module, "NetWitnessClientAPI")
    def test_init_full_config(self, m_netwitness_client_api):
        config_netwitness = MagicMock()
        config_netwitness.time_window = sentinel.time_window
        config_netwitness.max_retry = sentinel.max_retry
        offset = MagicMock()
        config_netwitness.offset = offset
        config = MagicMock()
        config.netwitness = config_netwitness

        expectation_service = module.NetWitnessExpectationService(config)

        self.assertEqual(expectation_service.config, config)
        m_netwitness_client_api.assert_called_with(config)
        self.assertEqual(
            expectation_service.client_api, m_netwitness_client_api.return_value
        )
        self.assertIsInstance(expectation_service.converter, module.Converter)
        self.assertEqual(expectation_service.time_window, sentinel.time_window)
        self.assertEqual(expectation_service.max_retry, sentinel.max_retry)
        self.assertEqual(expectation_service.offset, offset.total_seconds.return_value)

    @patch.object(module, "NetWitnessClientAPI")
    def test_init_configuration_error(self, m_netwitness_client_api):
        config = MagicMock()
        config.netwitness = None
        m_netwitness_client_api.side_effect = module.NetWitnessConfigurationError

        with self.assertRaises(module.NetWitnessConfigurationError):
            module.NetWitnessExpectationService(config)
            m_netwitness_client_api.assert_called_with(config)
