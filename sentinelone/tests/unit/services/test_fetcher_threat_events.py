import unittest
from unittest.mock import MagicMock, ANY, patch, sentinel

import src.services.fetcher_threat_events as module


class TestFetcherThreatEvents(unittest.TestCase):
    def test_init(self):
        client_api = sentinel.client_api

        fetcher = module.FetcherThreatEvents(client_api)

        self.assertEqual(fetcher.client_api, sentinel.client_api)

    @patch.object(module.FetcherThreatEvents, "_fetch_all_events_for_threat")
    def test_fetch_events_for_threat(self, m_fetch_all_events_for_threat):
        client_api = sentinel.client_api
        fetcher = module.FetcherThreatEvents(client_api)

        threat = MagicMock(spec=module.SentinelOneThreat)
        threat.threat_id = sentinel.threat_id
        process_names = MagicMock()

        all_events = fetcher.fetch_events_for_threat(threat, process_names)

        m_fetch_all_events_for_threat.assert_called_with(threat, 100)
        self.assertEqual(all_events, m_fetch_all_events_for_threat.return_value)

    @patch.object(module.FetcherThreatEvents, "_fetch_all_events_for_threat")
    def test_fetch_events_for_threat_fetching_error(self, m_fetch_all_events_for_threat):
        client_api = sentinel.client_api
        fetcher = module.FetcherThreatEvents(client_api)

        threat = MagicMock(spec=module.SentinelOneThreat)
        threat.threat_id = sentinel.threat_id
        process_names = MagicMock()
        m_fetch_all_events_for_threat.side_effect = module.SentinelOneAPIError

        with self.assertRaises(module.SentinelOneAPIError):
            fetcher.fetch_events_for_threat(threat, process_names)
            m_fetch_all_events_for_threat.assert_called_with(threat, 100)
