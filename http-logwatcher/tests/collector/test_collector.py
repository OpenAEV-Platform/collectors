import unittest
from unittest.mock import MagicMock, patch

import src.collector.collector as module

daemon_config_data = {
    "openaev_url": "http://fake.url",
    "openaev_token": "my_awesome_token",
}


@patch.object(module.ConfigLoader, "to_daemon_config", return_value=daemon_config_data)
class CollectorTest(unittest.TestCase):

    def test_collector_init(self, m_to_daemon_config):
        """
        testing the proper init of the Collector object
        and its reliance on ConfigLoader.m_to_daemon_config
        """
        collector = module.Collector()

        m_to_daemon_config.assert_called_once()
        self.assertEqual(collector.collector_type, "openaev_http_logwatcher")

    def test_collector_process_callback(self, _):
        """
        testing the link between process callback, expectation manager
        and detection helper in Collector
        """
        expectation_manager = MagicMock()
        oaev_detection_helper = MagicMock()
        collector = module.Collector()
        collector.expectation_manager = expectation_manager
        collector.oaev_detection_helper = oaev_detection_helper

        collector._process_callback()

        expectation_manager.process_expectations.assert_called_with(
            detection_helper=collector.oaev_detection_helper,
        )
