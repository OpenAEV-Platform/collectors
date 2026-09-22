import unittest
from unittest.mock import MagicMock, patch, sentinel

import src.services.client_api as module


class TestNetWitnessClientAPI(unittest.TestCase):
    @patch.object(module.NetWitnessClientAPI, "_create_session")
    def test_init_minimal(self, m_create_session):
        config_netwitness = MagicMock()
        config_netwitness.base_url = sentinel.base_url
        config_netwitness.token = None
        config_netwitness.username = sentinel.username
        config_netwitness.password = None
        config_netwitness.max_results = sentinel.max_results
        config_netwitness.console_url = sentinel.console_url
        offset = MagicMock()
        config_netwitness.offset = offset
        config_netwitness.max_retry = sentinel.max_retry
        config_netwitness.verify_ssl = sentinel.verify_ssl
        config_netwitness.time_window = None
        config = MagicMock()
        config.netwitness = config_netwitness

        client_api = module.NetWitnessClientAPI(config)

        self.assertEqual(client_api.base_url, str(sentinel.base_url))
        self.assertIsNone(client_api.token)
        self.assertEqual(client_api.username, sentinel.username)
        self.assertIsNone(client_api.password)
        self.assertEqual(client_api.max_results, sentinel.max_results)
        self.assertEqual(client_api.console_url, sentinel.console_url)
        self.assertEqual(client_api.offset, offset.total_seconds.return_value)
        self.assertEqual(client_api.max_retry, sentinel.max_retry)
        self.assertEqual(client_api.verify_ssl, sentinel.verify_ssl)
        self.assertEqual(client_api.time_window, module.timedelta(hours=module.DEFAULT_TIME_WINDOW_HOURS))
        self.assertEqual(client_api.session, m_create_session.return_value)
        self.assertIsInstance(client_api.parent_process_parser, module.ParentProcessParser)

    @patch.object(module.NetWitnessClientAPI, "_create_session")
    def test_init_full_config(self, m_create_session):
        config_netwitness = MagicMock()
        config_netwitness.base_url = sentinel.base_url
        token = MagicMock()
        config_netwitness.token = token
        config_netwitness.username = sentinel.username
        password = MagicMock()
        config_netwitness.password = password
        config_netwitness.max_results = sentinel.max_results
        config_netwitness.console_url = sentinel.console_url
        offset = MagicMock()
        config_netwitness.offset = offset
        config_netwitness.max_retry = sentinel.max_retry
        config_netwitness.verify_ssl = sentinel.verify_ssl
        config_netwitness.time_window = sentinel.time_window
        config = MagicMock()
        config.netwitness = config_netwitness

        client_api = module.NetWitnessClientAPI(config)

        self.assertEqual(client_api.base_url, str(sentinel.base_url))
        self.assertEqual(client_api.token, token.get_secret_value())
        self.assertEqual(client_api.username, sentinel.username)
        self.assertEqual(client_api.password, password.get_secret_value())
        self.assertEqual(client_api.max_results, sentinel.max_results)
        self.assertEqual(client_api.console_url, sentinel.console_url)
        self.assertEqual(client_api.offset, offset.total_seconds.return_value)
        self.assertEqual(client_api.max_retry, sentinel.max_retry)
        self.assertEqual(client_api.verify_ssl, sentinel.verify_ssl)
        self.assertEqual(client_api.time_window, sentinel.time_window)
        self.assertEqual(client_api.session, m_create_session.return_value)
        self.assertIsInstance(client_api.parent_process_parser, module.ParentProcessParser)

    @patch.object(module, "ipaddress")
    @patch.object(module.NetWitnessClientAPI, "_create_session")
    def test_normalize_query_ips(self, m_create_session, m_ipaddress):
        config_netwitness = MagicMock()
        config_netwitness.base_url = sentinel.base_url
        config_netwitness.token = None
        config_netwitness.username = sentinel.username
        config_netwitness.password = None
        config_netwitness.max_results = sentinel.max_results
        config_netwitness.console_url = sentinel.console_url
        offset = MagicMock()
        config_netwitness.offset = offset
        config_netwitness.max_retry = sentinel.max_retry
        config_netwitness.verify_ssl = sentinel.verify_ssl
        config_netwitness.time_window = None
        config = MagicMock()
        config.netwitness = config_netwitness

        client_api = module.NetWitnessClientAPI(config)

        ip = MagicMock()
        ips = [ip]

        valid_ips = client_api._normalize_query_ips(ips)

        self.assertEqual(valid_ips, [str(m_ipaddress.ip_address.return_value)])

    @patch.object(module, "ipaddress")
    @patch.object(module.NetWitnessClientAPI, "_create_session")
    def test_normalize_query_ips_value_error(self, m_create_session, m_ipaddress):
        config_netwitness = MagicMock()
        config_netwitness.base_url = sentinel.base_url
        config_netwitness.token = None
        config_netwitness.username = sentinel.username
        config_netwitness.password = None
        config_netwitness.max_results = sentinel.max_results
        config_netwitness.console_url = sentinel.console_url
        offset = MagicMock()
        config_netwitness.offset = offset
        config_netwitness.max_retry = sentinel.max_retry
        config_netwitness.verify_ssl = sentinel.verify_ssl
        config_netwitness.time_window = None
        config = MagicMock()
        config.netwitness = config_netwitness

        client_api = module.NetWitnessClientAPI(config)

        ip = MagicMock()
        ips = [ip]
        m_ipaddress.ip_address.side_effect = ValueError

        valid_ips = client_api._normalize_query_ips(ips)

        self.assertEqual(valid_ips, [])

    @patch.object(module.NetWitnessClientAPI, "_execute_query")
    @patch.object(module.NetWitnessClientAPI, "_create_session")
    def test_execute_query_with_retry(self, m_create_session, m_execute_query):
        config_netwitness = MagicMock()
        config_netwitness.base_url = sentinel.base_url
        config_netwitness.token = None
        config_netwitness.username = sentinel.username
        config_netwitness.password = None
        config_netwitness.max_results = sentinel.max_results
        config_netwitness.console_url = sentinel.console_url
        offset = MagicMock()
        config_netwitness.offset = offset
        config_netwitness.max_retry = sentinel.max_retry
        config_netwitness.verify_ssl = sentinel.verify_ssl
        config_netwitness.time_window = None
        config = MagicMock()
        config.netwitness = config_netwitness

        client_api = module.NetWitnessClientAPI(config)

        search_criteria = MagicMock()
        max_retries = MagicMock()
        offset_seconds = MagicMock()
        _alerts = [MagicMock()]
        m_execute_query.return_value = _alerts

        alerts = client_api._execute_query_with_retry(search_criteria, max_retries, offset_seconds)

        m_execute_query.assert_called_with(search_criteria, 0)
        self.assertEqual(alerts, _alerts)

    @patch.object(module.NetWitnessClientAPI, "_execute_query")
    @patch.object(module.NetWitnessClientAPI, "_create_session")
    def test_execute_query_with_retry_authentication_error(self, m_create_session, m_execute_query):
        config_netwitness = MagicMock()
        config_netwitness.base_url = sentinel.base_url
        config_netwitness.token = None
        config_netwitness.username = sentinel.username
        config_netwitness.password = None
        config_netwitness.max_results = sentinel.max_results
        config_netwitness.console_url = sentinel.console_url
        offset = MagicMock()
        config_netwitness.offset = offset
        config_netwitness.max_retry = sentinel.max_retry
        config_netwitness.verify_ssl = sentinel.verify_ssl
        config_netwitness.time_window = None
        config = MagicMock()
        config.netwitness = config_netwitness

        client_api = module.NetWitnessClientAPI(config)

        search_criteria = MagicMock()
        max_retries = MagicMock()
        offset_seconds = MagicMock()
        m_execute_query.side_effect = module.NetWitnessAuthenticationError

        with self.assertRaises(module.NetWitnessAuthenticationError):
            client_api._execute_query_with_retry(search_criteria, max_retries, offset_seconds)
            m_execute_query.assert_called_with(search_criteria, 0)
