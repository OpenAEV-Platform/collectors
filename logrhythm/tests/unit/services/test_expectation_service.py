import unittest
from unittest.mock import MagicMock, patch, sentinel

import src.services.expectation_service as module


class TestLogRhythmExpectationService(unittest.TestCase):
    @patch.object(module, "LogRhythmClientAPI")
    def test_init_minimal_config(self, m_logrhythm_client_api):
        config = MagicMock()
        config.logrhythm = None

        expectation_service = module.LogRhythmExpectationService(config)

        self.assertEqual(expectation_service.config, config)
        m_logrhythm_client_api.assert_called_with(config)
        self.assertEqual(
            expectation_service.client_api, m_logrhythm_client_api.return_value
        )
        self.assertIsInstance(expectation_service.converter, module.Converter)
        self.assertEqual(expectation_service.time_window, module.timedelta(hours=1))
        self.assertEqual(expectation_service.max_retry, 3)
        self.assertEqual(expectation_service.offset, 30)

    @patch.object(module, "LogRhythmClientAPI")
    def test_init_full_config(self, m_logrhythm_client_api):
        config_logrhythm = MagicMock()
        config_logrhythm.time_window = sentinel.time_window
        config_logrhythm.max_retry = sentinel.max_retry
        offset = MagicMock()
        config_logrhythm.offset = offset
        config = MagicMock()
        config.logrhythm = config_logrhythm

        expectation_service = module.LogRhythmExpectationService(config)

        self.assertEqual(expectation_service.config, config)
        m_logrhythm_client_api.assert_called_with(config)
        self.assertEqual(
            expectation_service.client_api, m_logrhythm_client_api.return_value
        )
        self.assertIsInstance(expectation_service.converter, module.Converter)
        self.assertEqual(expectation_service.time_window, sentinel.time_window)
        self.assertEqual(expectation_service.max_retry, sentinel.max_retry)
        self.assertEqual(expectation_service.offset, offset.total_seconds.return_value)

    @patch.object(module, "LogRhythmClientAPI")
    def test_init_configuration_error(self, m_logrhythm_client_api):
        config = MagicMock()
        config.logrhythm = None
        m_logrhythm_client_api.side_effect = module.LogRhythmConfigurationError

        with self.assertRaises(module.LogRhythmConfigurationError):
            module.LogRhythmExpectationService(config)
            m_logrhythm_client_api.assert_called_with(config)
