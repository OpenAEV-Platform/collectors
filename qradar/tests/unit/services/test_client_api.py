import unittest
from unittest.mock import MagicMock, patch, sentinel

import src.services.client_api as module


class TestQRadarClientAPI(unittest.TestCase):
    @patch.object(module.QRadarClientAPI, "_create_session")
    def test_init_minimal(self, m_create_session):
        config_qradar = MagicMock()
        config_qradar.base_url = sentinel.base_url
        config_qradar.token = None
        config_qradar.username = sentinel.username
        config_qradar.password = None
        config_qradar.api_version = sentinel.api_version
        config_qradar.data_source = None
        config_qradar.console_url = sentinel.console_url
        offset = MagicMock()
        config_qradar.offset = offset
        config_qradar.max_retry = sentinel.max_retry
        config_qradar.verify_ssl = sentinel.verify_ssl
        search_timeout = MagicMock()
        config_qradar.search_timeout = search_timeout
        poll_interval = MagicMock()
        config_qradar.poll_interval = poll_interval
        config_qradar.time_window = None
        config = MagicMock()
        config.qradar = config_qradar

        client_api = module.QRadarClientAPI(config)

        self.assertEqual(client_api.base_url, str(sentinel.base_url))
        self.assertIsNone(client_api.token)
        self.assertEqual(client_api.username, sentinel.username)
        self.assertIsNone(client_api.password)
        self.assertEqual(client_api.api_version, sentinel.api_version)
        self.assertEqual(client_api.data_source, "events")
        self.assertEqual(client_api.console_url, sentinel.console_url)
        self.assertEqual(client_api.offset, offset.total_seconds.return_value)
        self.assertEqual(client_api.max_retry, sentinel.max_retry)
        self.assertEqual(client_api.verify_ssl, sentinel.verify_ssl)
        self.assertEqual(
            client_api.search_timeout, search_timeout.total_seconds.return_value
        )
        self.assertEqual(
            client_api.poll_interval, poll_interval.total_seconds.return_value
        )
        self.assertEqual(
            client_api.time_window,
            module.timedelta(hours=module.DEFAULT_TIME_WINDOW_HOURS),
        )
        self.assertEqual(client_api.session, m_create_session.return_value)
        self.assertIsInstance(
            client_api.parent_process_parser, module.ParentProcessParser
        )

    @patch.object(module.QRadarClientAPI, "_create_session")
    def test_init_full_config(self, m_create_session):
        config_qradar = MagicMock()
        config_qradar.base_url = sentinel.base_url
        config_qradar.token = None
        config_qradar.username = sentinel.username
        config_qradar.password = None
        config_qradar.api_version = sentinel.api_version
        config_qradar.data_source = None
        config_qradar.console_url = sentinel.console_url
        offset = MagicMock()
        config_qradar.offset = offset
        config_qradar.max_retry = sentinel.max_retry
        config_qradar.verify_ssl = sentinel.verify_ssl
        search_timeout = MagicMock()
        config_qradar.search_timeout = search_timeout
        poll_interval = MagicMock()
        config_qradar.poll_interval = poll_interval
        config_qradar.time_window = sentinel.time_window
        config = MagicMock()
        config.qradar = config_qradar

        client_api = module.QRadarClientAPI(config)

        self.assertEqual(client_api.base_url, str(sentinel.base_url))
        self.assertIsNone(client_api.token)
        self.assertEqual(client_api.username, sentinel.username)
        self.assertIsNone(client_api.password)
        self.assertEqual(client_api.api_version, sentinel.api_version)
        self.assertEqual(client_api.data_source, "events")
        self.assertEqual(client_api.console_url, sentinel.console_url)
        self.assertEqual(client_api.offset, offset.total_seconds.return_value)
        self.assertEqual(client_api.max_retry, sentinel.max_retry)
        self.assertEqual(client_api.verify_ssl, sentinel.verify_ssl)
        self.assertEqual(
            client_api.search_timeout, search_timeout.total_seconds.return_value
        )
        self.assertEqual(
            client_api.poll_interval, poll_interval.total_seconds.return_value
        )
        self.assertEqual(client_api.time_window, sentinel.time_window)
        self.assertEqual(client_api.session, m_create_session.return_value)
        self.assertIsInstance(
            client_api.parent_process_parser, module.ParentProcessParser
        )

    @patch.object(module.QRadarClientAPI, "_execute_query")
    @patch.object(module.QRadarClientAPI, "_create_session")
    def test_execute_query_with_retry(self, m_create_session, m_execute_query):
        config_qradar = MagicMock()
        config_qradar.base_url = sentinel.base_url
        config_qradar.token = None
        config_qradar.username = sentinel.username
        config_qradar.password = None
        config_qradar.api_version = sentinel.api_version
        config_qradar.data_source = None
        config_qradar.console_url = sentinel.console_url
        offset = MagicMock()
        config_qradar.offset = offset
        config_qradar.max_retry = sentinel.max_retry
        config_qradar.verify_ssl = sentinel.verify_ssl
        search_timeout = MagicMock()
        config_qradar.search_timeout = search_timeout
        poll_interval = MagicMock()
        config_qradar.poll_interval = poll_interval
        config_qradar.time_window = None
        config = MagicMock()
        config.qradar = config_qradar

        client_api = module.QRadarClientAPI(config)

        search_criteria = MagicMock()
        max_retries = MagicMock()
        offset_seconds = MagicMock()
        _alerts = [MagicMock()]
        m_execute_query.return_value = _alerts

        alerts = client_api._execute_query_with_retry(
            search_criteria, max_retries, offset_seconds
        )

        m_execute_query.assert_called_with(search_criteria, 0)
        self.assertEqual(alerts, _alerts)

    @patch.object(module.QRadarClientAPI, "_execute_query")
    @patch.object(module.QRadarClientAPI, "_create_session")
    def test_execute_query_with_retry_authentication_error(
        self, m_create_session, m_execute_query
    ):
        config_qradar = MagicMock()
        config_qradar.base_url = sentinel.base_url
        config_qradar.token = None
        config_qradar.username = sentinel.username
        config_qradar.password = None
        config_qradar.api_version = sentinel.api_version
        config_qradar.data_source = None
        config_qradar.console_url = sentinel.console_url
        offset = MagicMock()
        config_qradar.offset = offset
        config_qradar.max_retry = sentinel.max_retry
        config_qradar.verify_ssl = sentinel.verify_ssl
        search_timeout = MagicMock()
        config_qradar.search_timeout = search_timeout
        poll_interval = MagicMock()
        config_qradar.poll_interval = poll_interval
        config_qradar.time_window = None
        config = MagicMock()
        config.qradar = config_qradar

        client_api = module.QRadarClientAPI(config)

        search_criteria = MagicMock()
        max_retries = MagicMock()
        offset_seconds = MagicMock()
        m_execute_query.side_effect = module.QRadarAuthenticationError

        with self.assertRaises(module.QRadarAuthenticationError):
            client_api._execute_query_with_retry(
                search_criteria, max_retries, offset_seconds
            )
        m_execute_query.assert_called_with(search_criteria, 0)
