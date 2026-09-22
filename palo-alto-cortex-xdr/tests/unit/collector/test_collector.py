import unittest
from unittest.mock import ANY, MagicMock, patch

import src.collector.collector as module

daemon_config_data = {
    "openaev_url": "http://fake.url",
    "openaev_token": "my_awesome_token",
}


class TestCollector(unittest.TestCase):
    @patch.object(module.Collector, "_process_callback")
    @patch.object(module, "ConfigLoader")
    def test_init(self, m_config_loader, m_process_callback):
        m_config_loader.return_value = MagicMock()
        m_config_loader.return_value.to_daemon_config.return_value = daemon_config_data

        collector = module.Collector()

        m_config_loader.assert_called_once()
        m_config_loader.return_value.to_daemon_config.assert_called_once()

    @patch.object(module, "ConfigLoader")
    def test_process_callback(self, m_config_loader):
        m_config_loader.return_value = MagicMock()
        m_config_loader.return_value.to_daemon_config.return_value = daemon_config_data

        collector = module.Collector()
        expectation_manager = MagicMock()
        collector.expectation_manager = expectation_manager
        oaev_detection_helper = MagicMock()
        collector.oaev_detection_helper = oaev_detection_helper

        collector._process_callback()

        expectation_manager.process_expectations.assert_called_with(detection_helper=oaev_detection_helper)

    @patch.object(module.os, "_exit")
    @patch.object(module, "ConfigLoader")
    def test_process_callback_keyboard_interrupt(self, m_config_loader, m_exit):
        m_config_loader.return_value = MagicMock()
        m_config_loader.return_value.to_daemon_config.return_value = daemon_config_data

        collector = module.Collector()
        expectation_manager = MagicMock()
        expectation_manager.process_expectations.side_effect = KeyboardInterrupt()
        collector.expectation_manager = expectation_manager
        oaev_detection_helper = MagicMock()
        collector.oaev_detection_helper = oaev_detection_helper

        collector._process_callback()
        expectation_manager.process_expectations.assert_called_with(detection_helper=oaev_detection_helper)
        m_exit.assert_called_with(0)

    @patch.object(module.os, "_exit")
    @patch.object(module, "ConfigLoader")
    def test_process_callback_system_exit(self, m_config_loader, m_exit):
        m_config_loader.return_value = MagicMock()
        m_config_loader.return_value.to_daemon_config.return_value = daemon_config_data

        collector = module.Collector()
        expectation_manager = MagicMock()
        expectation_manager.process_expectations.side_effect = SystemExit()
        collector.expectation_manager = expectation_manager
        oaev_detection_helper = MagicMock()
        collector.oaev_detection_helper = oaev_detection_helper

        collector._process_callback()
        expectation_manager.process_expectations.assert_called_with(detection_helper=oaev_detection_helper)
        m_exit.assert_called_with(0)
