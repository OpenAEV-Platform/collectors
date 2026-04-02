import unittest
from unittest.mock import MagicMock, patch

import src.collector.collector as module

daemon_config_data = {
    "openaev_url": "http://fake.url",
    "openaev_token": "my_awesome_token",
}


@patch.object(module, "ConfigLoader")
class CollectorTest(unittest.TestCase):

    def test_collector_init(self, m_configloader):
        """
        testing the proper init of the Collector object
        and its reliance on ConfigLoader.m_to_daemon_config
        """
        m_configloader.return_value.to_daemon_config.return_value = daemon_config_data
        collector = module.Collector()

        m_configloader.return_value.to_daemon_config.assert_called_once()
        self.assertEqual(collector.collector_type, "openaev_http_logwatcher")

    def test_collector_process_callback(self, m_configloader):
        """
        testing the link between process callback, expectation manager
        and detection helper in Collector
        """
        m_configloader.return_value.to_daemon_config.return_value = daemon_config_data
        expectation_manager = MagicMock()
        oaev_detection_helper = MagicMock()
        collector = module.Collector()
        collector.expectation_manager = expectation_manager
        collector.oaev_detection_helper = oaev_detection_helper

        collector._process_callback()

        expectation_manager.process_expectations.assert_called_with(
            detection_helper=collector.oaev_detection_helper,
        )
