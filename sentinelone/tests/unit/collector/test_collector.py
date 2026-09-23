import unittest
from unittest.mock import MagicMock, patch

import src.collector.collector as module

daemon_config_data = {
    "openaev_url": "http://fake.url",
    "openaev_token": "my_awesome_token",
}


class TestCollector(unittest.TestCase):
    @patch.object(module.Collector, "_process_callback")
    @patch.object(module, "SentinelOneConfig")
    def test_init(self, m_sentinel_one_config, m_process_callback):
        m_sentinel_one_config.return_value = MagicMock()
        m_sentinel_one_config.return_value.load.to_daemon_config.return_value = (
            daemon_config_data
        )

        module.Collector()

        m_sentinel_one_config.assert_called_once()
        m_sentinel_one_config.return_value.load.to_daemon_config.assert_called_once()

    @patch.object(module, "SentinelOneConfig")
    def test_process_callback(self, m_sentinel_one_config):
        m_sentinel_one_config.return_value = MagicMock()
        m_sentinel_one_config.return_value.load.to_daemon_config.return_value = (
            daemon_config_data
        )

        collector = module.Collector()
        expectation_manager = MagicMock()
        collector.expectation_manager = expectation_manager
        oaev_detection_helper = MagicMock()
        collector.oaev_detection_helper = oaev_detection_helper

        collector._process_callback()

        expectation_manager.process_expectations.assert_called_with(
            detection_helper=oaev_detection_helper
        )

    @patch.object(module.os, "_exit")
    @patch.object(module, "SentinelOneConfig")
    def test_process_callback_keyboard_interrupt(self, m_sentinel_one_config, m_exit):
        m_sentinel_one_config.return_value = MagicMock()
        m_sentinel_one_config.return_value.load.to_daemon_config.return_value = (
            daemon_config_data
        )

        collector = module.Collector()
        expectation_manager = MagicMock()
        expectation_manager.process_expectations.side_effect = KeyboardInterrupt()
        collector.expectation_manager = expectation_manager
        oaev_detection_helper = MagicMock()
        collector.oaev_detection_helper = oaev_detection_helper

        collector._process_callback()
        expectation_manager.process_expectations.assert_called_with(
            detection_helper=oaev_detection_helper
        )
        m_exit.assert_called_with(0)

    @patch.object(module.os, "_exit")
    @patch.object(module, "SentinelOneConfig")
    def test_process_callback_system_exit(self, m_sentinel_one_config, m_exit):
        m_sentinel_one_config.return_value = MagicMock()
        m_sentinel_one_config.return_value.load.to_daemon_config.return_value = (
            daemon_config_data
        )

        collector = module.Collector()
        expectation_manager = MagicMock()
        expectation_manager.process_expectations.side_effect = SystemExit()
        collector.expectation_manager = expectation_manager
        oaev_detection_helper = MagicMock()
        collector.oaev_detection_helper = oaev_detection_helper

        collector._process_callback()
        expectation_manager.process_expectations.assert_called_with(
            detection_helper=oaev_detection_helper
        )
        m_exit.assert_called_with(0)
