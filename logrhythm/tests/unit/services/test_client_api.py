import unittest
from unittest.mock import MagicMock, patch, sentinel

import src.services.client_api as module


class TestLogRhythmClientAPI(unittest.TestCase):
    @patch.object(module.LogRhythmClientAPI, "_create_session")
    def test_init_minimal(self, m_create_session):
        config_logrhythm = MagicMock()
        config_logrhythm.base_url = sentinel.base_url
        config_logrhythm.token = None
        config_logrhythm.username = sentinel.username
        config_logrhythm.password = None
        config_logrhythm.query_event_manager = sentinel.query_event_manager
        config_logrhythm.max_msgs = sentinel.max_msgs
        config_logrhythm.console_url = sentinel.console_url
        offset = MagicMock()
        config_logrhythm.offset = offset
        config_logrhythm.max_retry = sentinel.max_retry
        config_logrhythm.verify_ssl = sentinel.verify_ssl
        search_timeout = MagicMock()
        config_logrhythm.search_timeout = search_timeout
        poll_interval = MagicMock()
        config_logrhythm.poll_interval = poll_interval
        config_logrhythm.time_window = None
        config = MagicMock()
        config.logrhythm = config_logrhythm

        client_api = module.LogRhythmClientAPI(config)

        self.assertEqual(client_api.base_url, str(sentinel.base_url))
        self.assertIsNone(client_api.token)
        self.assertEqual(client_api.username, sentinel.username)
        self.assertIsNone(client_api.password)
        self.assertEqual(client_api.query_event_manager, sentinel.query_event_manager)
        self.assertEqual(client_api.max_msgs, sentinel.max_msgs)
        self.assertEqual(client_api.console_url, sentinel.console_url)
        self.assertEqual(client_api.offset, offset.total_seconds.return_value)
        self.assertEqual(client_api.max_retry, sentinel.max_retry)
        self.assertEqual(client_api.verify_ssl, sentinel.verify_ssl)
        self.assertEqual(client_api.search_timeout, search_timeout.total_seconds.return_value)
        self.assertEqual(client_api.poll_interval, poll_interval.total_seconds.return_value)
        self.assertEqual(client_api.time_window, module.timedelta(hours=module.DEFAULT_TIME_WINDOW_HOURS))
        self.assertEqual(client_api.session, m_create_session.return_value)
        self.assertIsInstance(client_api.parent_process_parser, module.ParentProcessParser)

    @patch.object(module.LogRhythmClientAPI, "_create_session")
    def test_init_full_config(self, m_create_session):
        config_logrhythm = MagicMock()
        config_logrhythm.base_url = sentinel.base_url
        token = MagicMock()
        config_logrhythm.token = token
        config_logrhythm.username = sentinel.username
        password = MagicMock()
        config_logrhythm.password = password
        config_logrhythm.query_event_manager = sentinel.query_event_manager
        config_logrhythm.max_msgs = sentinel.max_msgs
        config_logrhythm.console_url = sentinel.console_url
        offset = MagicMock()
        config_logrhythm.offset = offset
        config_logrhythm.max_retry = sentinel.max_retry
        config_logrhythm.verify_ssl = sentinel.verify_ssl
        search_timeout = MagicMock()
        config_logrhythm.search_timeout = search_timeout
        poll_interval = MagicMock()
        config_logrhythm.poll_interval = poll_interval
        config_logrhythm.time_window = sentinel.time_window
        config = MagicMock()
        config.logrhythm = config_logrhythm

        client_api = module.LogRhythmClientAPI(config)

        self.assertEqual(client_api.base_url, str(sentinel.base_url))
        self.assertEqual(client_api.token, token.get_secret_value.return_value)
        self.assertEqual(client_api.username, sentinel.username)
        self.assertEqual(client_api.password, password.get_secret_value.return_value)
        self.assertEqual(client_api.query_event_manager, sentinel.query_event_manager)
        self.assertEqual(client_api.max_msgs, sentinel.max_msgs)
        self.assertEqual(client_api.console_url, sentinel.console_url)
        self.assertEqual(client_api.offset, offset.total_seconds.return_value)
        self.assertEqual(client_api.max_retry, sentinel.max_retry)
        self.assertEqual(client_api.verify_ssl, sentinel.verify_ssl)
        self.assertEqual(client_api.search_timeout, search_timeout.total_seconds.return_value)
        self.assertEqual(client_api.poll_interval, poll_interval.total_seconds.return_value)
        self.assertEqual(client_api.time_window, sentinel.time_window)
        self.assertEqual(client_api.session, m_create_session.return_value)
        self.assertIsInstance(client_api.parent_process_parser, module.ParentProcessParser)

    @patch.object(module.LogRhythmClientAPI, "_execute_query")
    @patch.object(module.LogRhythmClientAPI, "_create_session")
    def test_execute_query_with_retry(self, m_create_session, m_execute_query):
        config_logrhythm = MagicMock()
        config_logrhythm.base_url = sentinel.base_url
        config_logrhythm.token = None
        config_logrhythm.username = sentinel.username
        config_logrhythm.password = None
        config_logrhythm.query_event_manager = sentinel.query_event_manager
        config_logrhythm.max_msgs = sentinel.max_msgs
        config_logrhythm.console_url = sentinel.console_url
        offset = MagicMock()
        config_logrhythm.offset = offset
        config_logrhythm.max_retry = sentinel.max_retry
        config_logrhythm.verify_ssl = sentinel.verify_ssl
        search_timeout = MagicMock()
        config_logrhythm.search_timeout = search_timeout
        poll_interval = MagicMock()
        config_logrhythm.poll_interval = poll_interval
        config_logrhythm.time_window = None
        config = MagicMock()
        config.logrhythm = config_logrhythm

        client_api = module.LogRhythmClientAPI(config)

        search_criteria = MagicMock()
        max_retries = MagicMock()
        offset_seconds = MagicMock()
        _alerts = [MagicMock()]
        m_execute_query.return_value = _alerts

        alerts = client_api._execute_query_with_retry(search_criteria, max_retries, offset_seconds)

        m_execute_query.assert_called_with(search_criteria, 0)
        self.assertEqual(alerts, _alerts)

    @patch.object(module.LogRhythmClientAPI, "_execute_query")
    @patch.object(module.LogRhythmClientAPI, "_create_session")
    def test_execute_query_with_retry_authentication_error(self, m_create_session, m_execute_query):
        config_logrhythm = MagicMock()
        config_logrhythm.base_url = sentinel.base_url
        config_logrhythm.token = None
        config_logrhythm.username = sentinel.username
        config_logrhythm.password = None
        config_logrhythm.query_event_manager = sentinel.query_event_manager
        config_logrhythm.max_msgs = sentinel.max_msgs
        config_logrhythm.console_url = sentinel.console_url
        offset = MagicMock()
        config_logrhythm.offset = offset
        config_logrhythm.max_retry = sentinel.max_retry
        config_logrhythm.verify_ssl = sentinel.verify_ssl
        search_timeout = MagicMock()
        config_logrhythm.search_timeout = search_timeout
        poll_interval = MagicMock()
        config_logrhythm.poll_interval = poll_interval
        config_logrhythm.time_window = None
        config = MagicMock()
        config.logrhythm = config_logrhythm

        client_api = module.LogRhythmClientAPI(config)

        search_criteria = MagicMock()
        max_retries = MagicMock()
        offset_seconds = MagicMock()
        m_execute_query.side_effect = module.LogRhythmAuthenticationError

        with self.assertRaises(module.LogRhythmAuthenticationError):
            client_api._execute_query_with_retry(search_criteria, max_retries, offset_seconds)
            m_execute_query.assert_called_with(search_criteria, 0)
